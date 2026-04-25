package common

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	dnsTypeA    uint16 = 1
	dnsTypeAAAA uint16 = 28
	dnsClassIN  uint16 = 1
)

// dohProviders lists DoH endpoints with their TLS hostname and pinned IPs
var dohProviders = []struct {
	url      string
	hostname string
	ips      []string
}{
	{"https://common.dot.dns.yandex.net/dns-query", "common.dot.dns.yandex.net", []string{"77.88.8.8", "77.88.8.1"}},
	{"https://dns.google/dns-query", "dns.google", []string{"8.8.8.8", "8.8.4.4"}},
	{"https://cloudflare-dns.com/dns-query", "cloudflare-dns.com", []string{"1.1.1.1", "1.0.0.1"}},
}

var (
	globalClients []*dohClient
	globalIdx     atomic.Uint64
)

// init initializes clients for all DoH providers
func init() {
	for _, p := range dohProviders {
		for _, ip := range p.ips {
			globalClients = append(globalClients, newDohClient(p.url, p.hostname, ip))
		}
	}
}

// dohClient performs DNS-over-HTTPS queries to a single pinned endpoint
type dohClient struct {
	url    string
	client *http.Client
}

// newDohClient creates a DoH client that dials pinnedIP directly, using hostname for TLS SNI
func newDohClient(dohURL, hostname, pinnedIP string) *dohClient {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(pinnedIP, "443"))
			if err != nil {
				return nil, err
			}

			tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}

			return tlsConn, nil
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}

	return &dohClient{
		url:    dohURL,
		client: &http.Client{Transport: transport, Timeout: 10 * time.Second},
	}
}

// buildQuery encodes a DNS query in wire format for the given hostname and record type
func buildQuery(id uint16, name string, qtype uint16) []byte {
	var qname []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		qname = append(qname, byte(len(label)))
		qname = append(qname, label...)
	}
	qname = append(qname, 0x00)

	buf := make([]byte, 0, 12+len(qname)+4)
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, 0x0100) // flags: RD=1
	buf = binary.BigEndian.AppendUint16(buf, 1)      // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // ANCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // NSCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // ARCOUNT
	buf = append(buf, qname...)
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, dnsClassIN)
	return buf
}

// skipName advances past a DNS name at off, handling compression pointers
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, fmt.Errorf("dns: name out of bounds at offset %d", off)
		}
		n := int(msg[off])
		if n == 0 {
			return off + 1, nil
		}
		if n&0xC0 == 0xC0 { // compression pointer
			return off + 2, nil
		}
		off += 1 + n
	}
}

// parseIPs extracts A and AAAA records from a raw DNS response
func parseIPs(msg []byte) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns: response too short")
	}

	if rcode := int(binary.BigEndian.Uint16(msg[2:4])) & 0xF; rcode == 2 {
		return nil, fmt.Errorf("dns: SERVFAIL")
	}

	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))

	off := 12
	for i := 0; i < qdcount; i++ {
		var err error
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}
		off += 4 // QTYPE + QCLASS
	}

	var ips []net.IP
	for i := 0; i < ancount; i++ {
		var err error
		if off, err = skipName(msg, off); err != nil {
			return nil, err
		}

		if off+10 > len(msg) {
			return nil, fmt.Errorf("dns: record header truncated")
		}

		rrType := binary.BigEndian.Uint16(msg[off:])
		off += 8 // TYPE(2) + CLASS(2) + TTL(4)
		rdlen := int(binary.BigEndian.Uint16(msg[off:]))
		off += 2

		if off+rdlen > len(msg) {
			return nil, fmt.Errorf("dns: rdata truncated")
		}

		rdata := msg[off : off+rdlen]
		off += rdlen

		switch rrType {
		case dnsTypeA:
			if rdlen == 4 {
				ip := make(net.IP, 4)
				copy(ip, rdata)
				ips = append(ips, ip)
			}
		case dnsTypeAAAA:
			if rdlen == 16 {
				ip := make(net.IP, 16)
				copy(ip, rdata)
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// query sends a DoH POST request for name/qtype and returns parsed IPs
func (c *dohClient) query(name string, qtype uint16) ([]net.IP, error) {
	body := buildQuery(uint16(globalIdx.Add(1)), name, qtype)
	resp, err := c.client.Post(c.url, "application/dns-message", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseIPs(data)
}

// Lookup resolves a hostname to IP addresses using native resolver with fallback to DoH
func Lookup(host string) ([]net.IP, error) {
	resolver := &net.Resolver{}
	if ips4, err := resolver.LookupIP(context.Background(), "ip4", host); err == nil && len(ips4) > 0 {
		if ips6, err := resolver.LookupIP(context.Background(), "ip6", host); err == nil {
			return append(ips4, ips6...), nil
		}
		return ips4, nil
	}

	if ips6, err := resolver.LookupIP(context.Background(), "ip6", host); err == nil && len(ips6) > 0 {
		return ips6, nil
	}

	if len(globalClients) == 0 {
		return nil, fmt.Errorf("no DoH clients configured")
	}

	start := int(globalIdx.Add(1)-1) % len(globalClients)
	var lastErr error
	for i := 0; i < len(globalClients); i++ {
		c := globalClients[(start+i)%len(globalClients)]
		ips, err := c.query(host, dnsTypeA)
		if err != nil {
			lastErr = err
			continue
		}

		if ips6, err := c.query(host, dnsTypeAAAA); err == nil {
			ips = append(ips, ips6...)
		}

		return ips, nil
	}

	return nil, fmt.Errorf("lookup %q: %w", host, lastErr)
}

// ResolveUDPAddr resolves an address using the global resolver for hostname lookup
func ResolveUDPAddr(addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	ips, err := Lookup(host)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}

// ResolverDialContext returns a DialContext function that uses the global DNS resolver
func ResolverDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		if net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, addr)
		}

		ips, err := Lookup(host)
		if err != nil {
			return nil, err
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses for %s", host)
		}

		var conn net.Conn
		for _, ip := range ips {
			conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}

		return nil, err
	}
}

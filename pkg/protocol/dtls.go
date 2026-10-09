package protocol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

const (
	dtlsMTU              = 1440            // DTLS record payload limit
	dtlsHandshakeTimeout = 5 * time.Second // DTLS handshake timeout
)

// DTLSHandler represents a DTLS session handler
type DTLSHandler struct {
	running atomic.Bool

	raw   *net.UDPConn
	demux *srtpDemux
	log   *slog.Logger
}

// ID returns the unique ID of this handler
func (D *DTLSHandler) ID() string {
	return "dtls"
}

// Start starts the server listener
func (D *DTLSHandler) Start(listenAddr string) error {
	if !D.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}
	if D.log == nil {
		D.log = slog.Default()
	}

	success := false
	defer func() {
		if !success {
			D.running.Store(false)
		}
	}()

	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid listen port %q: %w", portStr, err)
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}

	if addr.IP == nil {
		return fmt.Errorf("invalid listen IP: %q", host)
	}

	raw, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dtls udp listen failed: %w", err)
	}

	// a per-address demux, shared with SRTP, so masked records can bypass the DTLS stack
	D.raw = raw
	D.demux = newSRTPDemux(raw)
	go D.demux.run()

	D.log.Info("dtls listener started", "listen_addr", addr.String())
	success = true
	return nil
}

// Stop stops the server listener
func (D *DTLSHandler) Stop() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}
	if D.log == nil {
		D.log = slog.Default()
	}

	if D.demux != nil {
		D.demux.close()
		D.demux = nil
	}
	raw := D.raw
	D.raw = nil
	if raw == nil {
		return nil
	}
	err := raw.Close()
	if err != nil {
		D.log.Warn("dtls listener stop failed", "error", err)
		return err
	}
	D.log.Info("dtls listener stopped")
	return nil
}

// AcceptClients accepts new server clients
func (D *DTLSHandler) AcceptClients(ctx context.Context) (<-chan ServerClient, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}
	if D.log == nil {
		D.log = slog.Default()
	}

	out := make(chan ServerClient)
	demux := D.demux

	go func() {
		var inflight sync.WaitGroup
		defer close(out)
		defer inflight.Wait() // no handshake may send on out after it closes
		if demux == nil {
			return
		}
		for {
			select {
			case sess, ok := <-demux.newSess:
				if !ok {
					return
				}
				inflight.Add(1)
				go func() {
					defer inflight.Done()
					D.acceptSession(ctx, demux, sess, out)
				}()
			case <-ctx.Done():
				return
			case <-demux.closed:
				return
			}
		}
	}()

	return out, nil
}

// acceptSession runs the DTLS handshake for one client address
func (D *DTLSHandler) acceptSession(ctx context.Context, demux *srtpDemux, sess *srtpDemuxSession, out chan<- ServerClient) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		D.log.Warn("dtls server cert generation failed", "error", err)
		return
	}
	dConn := &demuxedConn{raw: demux.raw, ch: sess.dtlsCh, addr: sess.addr, closed: make(chan struct{})}
	conn, err := dtls.ServerWithOptions(dConn, sess.addr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithMTU(dtlsMTU),
	)
	if err != nil {
		D.log.Warn("dtls server init failed", "addr", sess.addr, "error", err)
		_ = dConn.Close()
		demux.remove(sess.addr.String())
		return
	}
	D.log.Debug("dtls server handshake started", "addr", sess.addr)
	hsCtx, cancel := context.WithTimeout(ctx, 2*dtlsHandshakeTimeout)
	err = conn.HandshakeContext(hsCtx)
	cancel()
	if err != nil {
		D.log.Warn("dtls handshake failed", "addr", sess.addr, "error", err)
		_ = conn.Close()
		_ = dConn.Close()
		demux.remove(sess.addr.String())
		return
	}
	D.log.Debug("dtls server handshake completed", "addr", sess.addr)

	dc, err := newDTLSConn(conn, demux.raw, sess.addr, false)
	if err != nil {
		D.log.Warn("dtls session setup failed", "addr", sess.addr, "error", err)
		_ = conn.Close()
		_ = dConn.Close()
		demux.remove(sess.addr.String())
		return
	}
	dc.onClose = func() {
		_ = dConn.Close()
		demux.remove(sess.addr.String())
	}
	sess.hook.Store(dc.hook())

	select {
	case out <- ServerClient{Address: sess.addr, Conn: dc}:
	case <-ctx.Done():
		_ = dc.Close()
	case <-demux.closed:
		_ = dc.Close()
	}
}

// Connect connects to a remote server directly or via TURN
func (D *DTLSHandler) Connect(ctx context.Context, dest net.Addr, relay TURNInfo, forceTURN bool) (net.Conn, error) {
	if D.log == nil {
		D.log = slog.Default()
	}
	if dest == nil {
		return nil, errors.New("dtls connect requires destination address")
	}

	if forceTURN {
		D.log.Debug("dtls connect using forced turn relay")
		underlay, remoteAddr, err := openTURNUnderlay(relay, dest, "dtls", D.log)
		if err != nil {
			return nil, err
		}
		conn, err := D.connectPacketConn(ctx, underlay, remoteAddr)
		if err != nil {
			_ = underlay.Close()
			return nil, err
		}
		return conn, nil
	}

	underlay, remoteAddr, err := openDirectUnderlay(dest, "dtls", D.log)
	if err != nil {
		return nil, err
	}

	conn, err := D.connectPacketConn(ctx, underlay, remoteAddr)
	if err == nil {
		D.log.Debug("dtls connect established via direct underlay")
		return conn, nil
	}

	_ = underlay.Close()

	if relay.Address == "" {
		return nil, err
	}

	D.log.Info("dtls direct connect failed, falling back to turn", "error", err)
	turnUnderlay, turnRemote, turnErr := openTURNUnderlay(relay, dest, "dtls", D.log)
	if turnErr != nil {
		return nil, errors.Join(err, turnErr)
	}
	conn, connErr := D.connectPacketConn(ctx, turnUnderlay, turnRemote)
	if connErr != nil {
		_ = turnUnderlay.Close()
		return nil, errors.Join(err, connErr)
	}

	D.log.Debug("dtls connect established via turn relay")
	return conn, nil
}

// SetLogger changes the slog logger instance
func (D *DTLSHandler) SetLogger(log *slog.Logger) {
	D.log = log

	if D.log == nil {
		D.log = slog.Default()
	}
}

// connectPacketConn upgrades a packet underlay into an established DTLS session
func (D *DTLSHandler) connectPacketConn(ctx context.Context, underlay net.PacketConn, remoteAddr net.Addr) (net.Conn, error) {
	if underlay == nil {
		return nil, errors.New("dtls connect requires packet underlay")
	}
	if remoteAddr == nil {
		return nil, errors.New("dtls connect requires remote address")
	}

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("failed to generate dtls certificate: %w", err)
	}

	icpt := &interceptPacketConn{PacketConn: underlay}
	conn, err := dtls.ClientWithOptions(icpt, remoteAddr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMTU(dtlsMTU),
	)

	if err != nil {
		return nil, fmt.Errorf("dtls client init failed: %w", err)
	}

	D.log.Debug("dtls client initialized", "underlay_local", underlay.LocalAddr().String(), "remote", remoteAddr.String())

	_ = conn.SetDeadline(time.Now().Add(dtlsHandshakeTimeout))

	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dtls client handshake failed: %w", err)
	}

	_ = conn.SetDeadline(time.Time{})

	D.log.Debug("dtls client handshake completed", "underlay_local", underlay.LocalAddr().String(), "remote", remoteAddr.String())

	dc, err := newDTLSConn(conn, underlay, remoteAddr, true)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dtls session setup failed: %w", err)
	}
	dc.underlay = underlay
	icpt.hook.Store(dc.hook())

	if maskingRequested(ctx) {
		dc.negotiateMask(ctx)
		D.log.Debug("dtls masking negotiation finished", "masked", dc.Masked())
	}
	return dc, nil
}

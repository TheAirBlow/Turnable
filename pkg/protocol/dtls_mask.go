package protocol

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
)

const (
	dtlsRecordHeaderLen = 13 // content type, version, epoch, sequence, length
	dtlsExplicitNonce   = 8  // AES-GCM explicit nonce carried by real records
	dtlsGCMTag          = 16
	dtlsAppData         = 23
)

// hookFn intercepts raw records before pion sees them; it returns true when it consumed the packet
type hookFn func(pkt []byte) bool

// interceptPacketConn lets a dtlsConn take masked records off the underlay before pion reads them
type interceptPacketConn struct {
	net.PacketConn
	hook atomic.Pointer[hookFn]
}

func (c *interceptPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || n == 0 {
			return n, addr, err
		}
		if h := c.hook.Load(); h != nil && (*h)(b[:n]) {
			continue
		}
		return n, addr, nil
	}
}

// dtlsConn is a DTLS session that can switch to masked records once negotiated
type dtlsConn struct {
	*dtls.Conn
	raw      net.PacketConn // writes masked records directly
	remote   net.Addr
	underlay net.PacketConn // closed with the conn on the client side
	onClose  func()

	mask       *masker
	isClient   bool
	sendMasked atomic.Bool
	recvMasked atomic.Bool

	masked chan []byte // intercepted masked records
	plain  chan []byte // records decrypted by pion
	pumpMu sync.Mutex
	pumped bool

	wmu  sync.Mutex
	wseq uint64
	wbuf []byte

	closed    chan struct{}
	closeOnce sync.Once
	dl        deadlineState
}

func newDTLSConn(conn *dtls.Conn, raw net.PacketConn, remote net.Addr, isClient bool) (*dtlsConn, error) {
	state, ok := conn.ConnectionState()
	if !ok {
		return nil, errors.New("failed to get dtls connection state")
	}
	mask, err := newMasker(&state, isClient)
	if err != nil {
		return nil, err
	}
	return &dtlsConn{
		Conn: conn, raw: raw, remote: remote, mask: mask, isClient: isClient,
		masked: make(chan []byte, 2048),
		plain:  make(chan []byte, 256),
		wbuf:   make([]byte, 0, dtlsMTU+64),
		closed: make(chan struct{}),
	}, nil
}

// intercept takes masked records once the peer switched; everything else goes to pion
func (c *dtlsConn) intercept(pkt []byte) bool {
	if !c.recvMasked.Load() || pkt[0] != dtlsAppData {
		return false
	}
	select {
	case c.masked <- append([]byte(nil), pkt...):
	default: // reader behind: drop, as UDP would
	}
	return true
}

func (c *dtlsConn) hook() *hookFn {
	h := hookFn(c.intercept)
	return &h
}

// pump moves pion-decrypted records into the plain channel
func (c *dtlsConn) startPump() {
	c.pumpMu.Lock()
	defer c.pumpMu.Unlock()
	if c.pumped {
		return
	}
	c.pumped = true
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := c.Conn.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				_ = c.Close()
				return
			}
			select {
			case c.plain <- append([]byte(nil), buf[:n]...):
			case <-c.closed:
				return
			}
		}
	}()
}

// Masked reports whether masking replaced DTLS record encryption
func (c *dtlsConn) Masked() bool { return c.sendMasked.Load() }

// Read returns the next record payload, from pion or from the masked path
func (c *dtlsConn) Read(b []byte) (int, error) {
	c.startPump()
	for {
		dl := c.dl.getCh()
		select {
		case rec := <-c.masked:
			if len(rec) < dtlsRecordHeaderLen+dtlsExplicitNonce+dtlsGCMTag {
				continue
			}
			index := binary.BigEndian.Uint64(rec[3:11]) & (1<<48 - 1)
			payload := rec[dtlsRecordHeaderLen+dtlsExplicitNonce : len(rec)-dtlsGCMTag]
			c.mask.unmaskInPlace(0, index, payload)
			return copy(b, payload), nil
		case p := <-c.plain:
			if c.handleMaskControl(p) {
				if c.isClient {
					return 0, nil // lets negotiateMask return without waiting out its deadline
				}
				continue
			}
			return copy(b, p), nil
		case <-c.closed:
			return 0, net.ErrClosed
		case <-dl:
			if c.dl.isExpired() {
				return 0, os.ErrDeadlineExceeded
			}
		}
	}
}

func (c *dtlsConn) handleMaskControl(p []byte) bool {
	if len(p) != maskHelloLen {
		return false
	}
	switch {
	case !c.isClient && [maskHelloLen]byte(p) == maskHello:
		if _, err := c.Conn.Write(maskAck[:]); err == nil {
			c.recvMasked.Store(true)
			c.sendMasked.Store(true)
		}
		return true
	case c.isClient && [maskHelloLen]byte(p) == maskAck:
		c.recvMasked.Store(true)
		c.sendMasked.Store(true)
		return true
	}
	return false
}

// Write sends b as a DTLS application-data record, real or masked
func (c *dtlsConn) Write(b []byte) (int, error) {
	if !c.sendMasked.Load() {
		return c.Conn.Write(b)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	seq := c.wseq
	c.wseq++
	n := dtlsExplicitNonce + len(b) + dtlsGCMTag
	buf := c.wbuf[:dtlsRecordHeaderLen+dtlsExplicitNonce]
	buf[0] = dtlsAppData
	buf[1], buf[2] = 0xfe, 0xfd
	binary.BigEndian.PutUint64(buf[3:], 1<<48|seq) // epoch 1, 48-bit sequence
	binary.BigEndian.PutUint16(buf[11:], uint16(n))
	copy(buf[dtlsRecordHeaderLen:], buf[3:11]) // GCM explicit nonce mirrors epoch|seq, as pion does
	buf = append(buf, b...)
	c.mask.maskInPlace(0, seq, buf[dtlsRecordHeaderLen+dtlsExplicitNonce:])
	buf = append(buf, zeroTag[:dtlsGCMTag]...)
	c.mask.fillTag(buf[len(buf)-dtlsGCMTag:])
	c.wbuf = buf[:0]
	if _, err := c.raw.WriteTo(buf, c.remote); err != nil {
		return 0, err
	}
	return len(b), nil
}

// negotiateMask offers masking; old servers never ack and the conn stays fully encrypted
func (c *dtlsConn) negotiateMask(ctx context.Context) {
	buf := make([]byte, dtlsMTU)
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	for attempt := 0; attempt < 3 && ctx.Err() == nil; attempt++ {
		if _, err := c.Conn.Write(maskHello[:]); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		for !c.recvMasked.Load() {
			if _, err := c.Read(buf); err != nil {
				break
			}
		}
		if c.recvMasked.Load() {
			return
		}
	}
}

// SetDeadline sets the read deadline
func (c *dtlsConn) SetDeadline(t time.Time) error { c.dl.set(t); return nil }

// SetReadDeadline sets the read deadline
func (c *dtlsConn) SetReadDeadline(t time.Time) error { c.dl.set(t); return nil }

// SetWriteDeadline is a no-op: UDP writes do not block
func (c *dtlsConn) SetWriteDeadline(time.Time) error { return nil }

// RemoteAddr returns the peer address
func (c *dtlsConn) RemoteAddr() net.Addr { return c.remote }

// Close closes the DTLS session and, on the client, the underlay
func (c *dtlsConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		c.dl.close()
		if c.onClose != nil {
			c.onClose()
		}
		err = c.Conn.Close()
		if c.underlay != nil {
			err = errors.Join(err, c.underlay.Close())
		}
	})
	return err
}

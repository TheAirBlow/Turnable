package protocol

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

const (
	srtpPayloadType = 100  // RTP payload type used to mimic VP8 WebRTC traffic
	srtpMTU         = 1440 // SRTP record payload limit
)

// SRTPHandler disguises VPN traffic as WebRTC SRTP
type SRTPHandler struct {
	running atomic.Bool
	raw     *net.UDPConn
	demux   *srtpDemux
	log     *slog.Logger
}

// ID returns the unique ID of this handler
func (S *SRTPHandler) ID() string { return "srtp" }

// SetLogger changes the slog logger instance
func (S *SRTPHandler) SetLogger(log *slog.Logger) {
	S.log = log
	if S.log == nil {
		S.log = slog.Default()
	}
}

// Start starts the server listener
func (S *SRTPHandler) Start(listenAddr string) error {
	if !S.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			S.running.Store(false)
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
		return fmt.Errorf("srtp udp listen failed: %w", err)
	}

	S.raw = raw
	S.demux = newSRTPDemux(raw)
	go S.demux.run()

	slog.Info("srtp listener started", "listen_addr", addr.String())
	success = true
	return nil
}

// Stop stops the server listener
func (S *SRTPHandler) Stop() error {
	if !S.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	if S.demux != nil {
		S.demux.close()
		S.demux = nil
	}

	raw := S.raw
	S.raw = nil
	if raw != nil {
		if err := raw.Close(); err != nil {
			slog.Warn("srtp listener stop failed", "error", err)
			return err
		}
	}

	slog.Info("srtp listener stopped")
	return nil
}

// AcceptClients accepts new server clients
func (S *SRTPHandler) AcceptClients(ctx context.Context) (<-chan ServerClient, error) {
	if !S.running.Load() {
		return nil, errors.New("not running")
	}

	out := make(chan ServerClient)
	demux := S.demux

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
					S.acceptSession(ctx, demux, sess, out)
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

// acceptSession performs the DTLS-SRTP handshake for one incoming client
func (S *SRTPHandler) acceptSession(ctx context.Context, demux *srtpDemux, sess *srtpDemuxSession, out chan<- ServerClient) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		slog.Warn("srtp server cert generation failed", "error", err)
		return
	}

	dConn := &demuxedConn{raw: demux.raw, ch: sess.dtlsCh, addr: sess.addr, closed: make(chan struct{})}
	dtlsConn, err := dtls.ServerWithOptions(dConn, sess.addr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithMTU(srtpMTU),
	)
	if err != nil {
		slog.Warn("srtp dtls server init failed", "addr", sess.addr, "error", err)
		_ = dConn.Close()
		return
	}

	slog.Debug("srtp server handshake started", "addr", sess.addr)
	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		slog.Warn("srtp server handshake failed", "addr", sess.addr, "error", err)
		_ = dtlsConn.Close()
		_ = dConn.Close()
		return
	}
	slog.Debug("srtp server handshake completed", "addr", sess.addr)

	conn, err := newSRTPConn(demux.raw, sess.addr, dtlsConn, sess.srtpCh, false)
	if err != nil {
		slog.Warn("srtp context setup failed", "addr", sess.addr, "error", err)
		_ = dtlsConn.Close()
		_ = dConn.Close()
		return
	}
	conn.onClose = func() { demux.remove(sess.addr.String()) }

	select {
	case out <- ServerClient{Address: sess.addr, Conn: conn}:
	case <-ctx.Done():
		_ = conn.Close()
	case <-demux.closed:
		_ = conn.Close()
	}
}

// Connect connects to a remote server directly or via TURN
func (S *SRTPHandler) Connect(ctx context.Context, dest net.Addr, relay TURNInfo, forceTURN bool) (net.Conn, error) {
	if S.log == nil {
		S.log = slog.Default()
	}
	if dest == nil {
		return nil, errors.New("srtp connect requires destination address")
	}

	if forceTURN {
		S.log.Debug("srtp connect using forced turn relay")
		underlay, remoteAddr, err := openTURNUnderlay(relay, dest, "srtp", S.log)
		if err != nil {
			return nil, err
		}
		conn, err := S.connectPacketConn(ctx, underlay, remoteAddr)
		if err != nil {
			_ = underlay.Close()
			return nil, err
		}
		return conn, nil
	}

	underlay, remoteAddr, err := openDirectUnderlay(dest, "srtp", S.log)
	if err != nil {
		return nil, err
	}

	conn, err := S.connectPacketConn(ctx, underlay, remoteAddr)
	if err == nil {
		S.log.Debug("srtp connect established via direct underlay")
		return conn, nil
	}
	_ = underlay.Close()

	if relay.Address == "" {
		return nil, err
	}

	S.log.Info("srtp direct connect failed, falling back to turn", "error", err)
	turnUnderlay, turnRemote, turnErr := openTURNUnderlay(relay, dest, "srtp", S.log)
	if turnErr != nil {
		return nil, errors.Join(err, turnErr)
	}
	conn, connErr := S.connectPacketConn(ctx, turnUnderlay, turnRemote)
	if connErr != nil {
		_ = turnUnderlay.Close()
		return nil, errors.Join(err, connErr)
	}

	S.log.Debug("srtp connect established via turn relay")
	return conn, nil
}

// connectPacketConn performs DTLS-SRTP handshake and returns an SRTP wrapped connection
func (S *SRTPHandler) connectPacketConn(ctx context.Context, underlay net.PacketConn, remoteAddr net.Addr) (net.Conn, error) {
	if underlay == nil {
		return nil, errors.New("srtp connect requires packet underlay")
	}
	if remoteAddr == nil {
		return nil, errors.New("srtp connect requires remote address")
	}

	dtlsCh := make(chan []byte, 64)
	srtpCh := make(chan []byte, 2048)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := underlay.ReadFrom(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			if isDTLSByte(buf[0]) {
				select {
				case dtlsCh <- pkt:
				default:
				}
			} else if isRTPByte(buf[0]) {
				select {
				case srtpCh <- pkt:
				default:
				}
			}
		}
	}()

	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("failed to generate dtls certificate: %w", err)
	}

	dConn := &demuxedConn{raw: underlay, ch: dtlsCh, addr: remoteAddr, closed: make(chan struct{})}
	dtlsConn, err := dtls.ClientWithOptions(dConn, remoteAddr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithSRTPProtectionProfiles(dtls.SRTP_AES128_CM_HMAC_SHA1_80),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithMTU(srtpMTU),
	)
	if err != nil {
		_ = dConn.Close()
		return nil, fmt.Errorf("srtp dtls client init failed: %w", err)
	}

	S.log.Debug("srtp client handshake started", "remote", remoteAddr.String())

	_ = dtlsConn.SetDeadline(time.Now().Add(dtlsHandshakeTimeout))

	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		_ = dtlsConn.Close()
		_ = dConn.Close()
		return nil, fmt.Errorf("srtp client handshake failed: %w", err)
	}

	_ = dtlsConn.SetDeadline(time.Time{})

	S.log.Debug("srtp client handshake completed", "remote", remoteAddr.String())

	conn, err := newSRTPConn(underlay, remoteAddr, dtlsConn, srtpCh, true)
	if err != nil {
		_ = dtlsConn.Close()
		_ = dConn.Close()
		return nil, fmt.Errorf("srtp context setup failed: %w", err)
	}
	conn.underlay = underlay

	if maskingRequested(ctx) {
		conn.negotiateMask(ctx)
		S.log.Debug("srtp masking negotiation finished", "masked", conn.Masked())
	}

	return conn, nil
}

// isDTLSByte returns true if the first byte indicates a DTLS record
func isDTLSByte(b byte) bool { return b >= 20 && b <= 63 }

// isRTPByte returns true if the first byte indicates an RTP/SRTP packet
func isRTPByte(b byte) bool { return b >= 128 && b <= 191 }

// srtpDemux classifies incoming UDP packets as DTLS or SRTP and routes them to per session channels
type srtpDemux struct {
	raw       *net.UDPConn
	mu        sync.RWMutex
	sessions  map[string]*srtpDemuxSession
	newSess   chan *srtpDemuxSession
	closed    chan struct{}
	closeOnce sync.Once
}

// srtpDemuxSession holds per-client channels for a server-side SRTP session
type srtpDemuxSession struct {
	dtlsCh chan []byte
	srtpCh chan []byte
	addr   net.Addr
	hook   atomic.Pointer[hookFn] // takes masked DTLS records before the DTLS stack
}

// remove deletes a session from the demux map by address key
func (d *srtpDemux) remove(key string) {
	d.mu.Lock()
	delete(d.sessions, key)
	d.mu.Unlock()
}

// newSRTPDemux creates a new srtpDemux for the given UDP connection
func newSRTPDemux(raw *net.UDPConn) *srtpDemux {
	return &srtpDemux{
		raw:      raw,
		sessions: make(map[string]*srtpDemuxSession),
		newSess:  make(chan *srtpDemuxSession, 16),
		closed:   make(chan struct{}),
	}
}

// close signals the demux loop to stop
func (d *srtpDemux) close() {
	d.closeOnce.Do(func() { close(d.closed) })
}

// run reads from the raw UDP socket and routes packets to per-session channels
func (d *srtpDemux) run() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := d.raw.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.closed:
				return
			default:
				continue
			}
		}
		if n == 0 {
			continue
		}

		key := addr.String()
		d.mu.RLock()
		sess, ok := d.sessions[key]
		d.mu.RUnlock()

		if !ok {
			sess = &srtpDemuxSession{
				dtlsCh: make(chan []byte, 64),
				srtpCh: make(chan []byte, 2048),
				addr:   addr,
			}
			d.mu.Lock()
			d.sessions[key] = sess
			d.mu.Unlock()

			select {
			case d.newSess <- sess:
			case <-d.closed:
				return
			}
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if h := sess.hook.Load(); h != nil && (*h)(pkt) {
			continue
		}
		if isDTLSByte(buf[0]) {
			select {
			case sess.dtlsCh <- pkt:
			default:
			}
		} else if isRTPByte(buf[0]) {
			select {
			case sess.srtpCh <- pkt:
			default:
			}
		}
	}
}

// deadlineState manages a read deadline capable channel
type deadlineState struct {
	mu     sync.Mutex
	signal *deadlineSignal
	stop   func()
	exp    time.Time
}

// deadlineSignal manages the deadline signal
type deadlineSignal struct {
	ch   chan struct{}
	once sync.Once
}

// close closes the deadline channel
func (s *deadlineSignal) close() {
	if s == nil {
		return
	}
	s.once.Do(func() { close(s.ch) })
}

// getCh returns the current deadline channel, creating one if needed
func (d *deadlineState) getCh() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.signal == nil {
		d.signal = &deadlineSignal{ch: make(chan struct{})}
	}
	return d.signal.ch
}

// isExpired reports whether the deadline has actually passed
func (d *deadlineState) isExpired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.exp.IsZero() && !time.Now().Before(d.exp)
}

// set updates the deadline, waking any blocked reads so they re-check
func (d *deadlineState) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stop != nil {
		d.stop()
		d.stop = nil
	}

	if d.signal != nil {
		d.signal.close()
	}

	d.signal = &deadlineSignal{ch: make(chan struct{})}
	d.exp = t
	if !t.IsZero() {
		dur := time.Until(t)
		if dur <= 0 {
			d.signal.close()
			return
		}
		signal := d.signal
		timer := time.AfterFunc(dur, signal.close)
		d.stop = func() { timer.Stop() }
	}
}

// close cancels any pending timer and closes the current deadline channel
func (d *deadlineState) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stop != nil {
		d.stop()
		d.stop = nil
	}
	if d.signal != nil {
		d.signal.close()
		d.signal = nil
	}
	d.exp = time.Time{}
}

// demuxedConn adapts a channel of packets into a net.PacketConn
type demuxedConn struct {
	raw       net.PacketConn
	ch        chan []byte
	addr      net.Addr
	closed    chan struct{}
	closeOnce sync.Once
	dl        deadlineState
}

// ReadFrom reads an incoming packet and blocks
func (d *demuxedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		dl := d.dl.getCh()
		select {
		case pkt, ok := <-d.ch:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return copy(b, pkt), d.addr, nil
		case <-d.closed:
			return 0, nil, net.ErrClosed
		case <-dl:
			if d.dl.isExpired() {
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
	}
}

// WriteTo writes a packet directly to the raw connection
func (d *demuxedConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return d.raw.WriteTo(b, addr)
}

// LocalAddr returns the local address of the underlying conn
func (d *demuxedConn) LocalAddr() net.Addr { return d.raw.LocalAddr() }

// SetDeadline sets both the read and write deadlines
func (d *demuxedConn) SetDeadline(t time.Time) error {
	if err := d.raw.SetDeadline(t); err != nil {
		return err
	}
	d.dl.set(t)
	return nil
}

// SetReadDeadline sets the deadline for future ReadFrom calls
func (d *demuxedConn) SetReadDeadline(t time.Time) error { d.dl.set(t); return nil }

// SetWriteDeadline sets the write deadline on the underlying conn
func (d *demuxedConn) SetWriteDeadline(t time.Time) error { return d.raw.SetWriteDeadline(t) }

// Close signals the demuxedConn as closed without closing the underlay
func (d *demuxedConn) Close() error {
	d.closeOnce.Do(func() {
		d.dl.close()
		close(d.closed)
	})
	return nil
}

// newSRTPConn extracts keying material from DTLS and builds an SRTP wrapped connection
func newSRTPConn(raw net.PacketConn, remote net.Addr, dtlsConn *dtls.Conn, incoming chan []byte, isClient bool) (*srtpConn, error) {
	state, ok := dtlsConn.ConnectionState()
	if !ok {
		return nil, errors.New("failed to get dtls connection state")
	}

	srtpCfg := &srtp.Config{Profile: srtp.ProtectionProfileAes128CmHmacSha1_80}
	if err := srtpCfg.ExtractSessionKeysFromDTLS(&state, isClient); err != nil {
		return nil, fmt.Errorf("failed to extract srtp keys: %w", err)
	}

	encCtx, err := srtp.CreateContext(
		srtpCfg.Keys.LocalMasterKey, srtpCfg.Keys.LocalMasterSalt, srtpCfg.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to create srtp encrypt context: %w", err)
	}

	decCtx, err := srtp.CreateContext(
		srtpCfg.Keys.RemoteMasterKey, srtpCfg.Keys.RemoteMasterSalt, srtpCfg.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to create srtp decrypt context: %w", err)
	}

	var ssrcBuf [4]byte
	if _, err := rand.Read(ssrcBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to generate ssrc: %w", err)
	}

	mask, err := newMasker(&state, isClient)
	if err != nil {
		return nil, fmt.Errorf("failed to derive mask keys: %w", err)
	}

	return &srtpConn{
		raw:      raw,
		remote:   remote,
		dtlsConn: dtlsConn,
		encCtx:   encCtx,
		decCtx:   decCtx,
		incoming: incoming,
		ssrc:     binary.BigEndian.Uint32(ssrcBuf[:]),
		closed:   make(chan struct{}),
		mask:     mask,
		isClient: isClient,
		wbuf:     make([]byte, 0, srtpMTU+64),
		ebuf:     make([]byte, 0, srtpMTU+64),
		rbuf:     make([]byte, 0, srtpMTU+64),
	}, nil
}

// srtpHeaderLen is the fixed RTP header we emit: no CSRCs, no extensions
const srtpHeaderLen = 12

// srtpTagLen is the AES128_CM_HMAC_SHA1_80 auth tag length, imitated by masked packets
const srtpTagLen = 10

var zeroTag [16]byte

// negotiateMask offers masking to the server and switches on its ack; old servers never ack
func (c *srtpConn) negotiateMask(ctx context.Context) {
	buf := make([]byte, srtpMTU)
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	for attempt := 0; attempt < 3 && ctx.Err() == nil; attempt++ {
		if _, err := c.Write(maskHello[:]); err != nil {
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

// Masked reports whether masking replaced SRTP encryption on this conn
func (c *srtpConn) Masked() bool { return c.sendMasked.Load() }

// srtpConn wraps a raw PacketConn with RTP framing and SRTP encryption
type srtpConn struct {
	raw      net.PacketConn
	remote   net.Addr
	dtlsConn *dtls.Conn
	encCtx   *srtp.Context
	decCtx   *srtp.Context
	incoming chan []byte
	ssrc     uint32

	mu        sync.Mutex
	seq       uint16
	ts        uint32
	closed    chan struct{}
	closeOnce sync.Once
	onClose   func()
	underlay  net.PacketConn

	dl deadlineState

	mask       *masker
	isClient   bool
	sendMasked atomic.Bool
	recvMasked atomic.Bool
	roc        uint32 // send rollover counter, guarded by mu
	wbuf, ebuf []byte // write buffers, guarded by mu
	readMu     sync.Mutex
	rbuf       []byte // read buffer, guarded by readMu
	recvROC    rocTracker
}

// Read decrypts (or unmasks) an incoming packet and returns its payload
func (c *srtpConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		dl := c.dl.getCh()
		select {
		case pkt, ok := <-c.incoming:
			if !ok {
				return 0, net.ErrClosed
			}
			if c.recvMasked.Load() {
				if len(pkt) < srtpHeaderLen+srtpTagLen || pkt[0]&0x3f != 0 {
					continue
				}
				seq := binary.BigEndian.Uint16(pkt[2:])
				ssrc := binary.BigEndian.Uint32(pkt[8:])
				payload := pkt[srtpHeaderLen : len(pkt)-srtpTagLen]
				c.mask.unmaskInPlace(ssrc, c.recvROC.index(seq), payload)
				return copy(b, payload), nil
			}
			decrypted, err := c.decCtx.DecryptRTP(c.rbuf[:0], pkt, nil)
			if err != nil {
				continue
			}
			var hdr rtp.Header
			hdrLen, err := hdr.Unmarshal(decrypted)
			if err != nil {
				continue
			}
			payload := decrypted[hdrLen:]
			if c.handleMaskControl(payload, hdr.SequenceNumber) {
				if c.isClient {
					return 0, nil // lets negotiateMask return without waiting out its deadline
				}
				continue
			}
			return copy(b, payload), nil
		case <-c.closed:
			return 0, net.ErrClosed
		case <-dl:
			if c.dl.isExpired() {
				return 0, os.ErrDeadlineExceeded
			}
		}
	}
}

// handleMaskControl consumes masking negotiation messages, returning true if payload was one
func (c *srtpConn) handleMaskControl(payload []byte, seq uint16) bool {
	if len(payload) != maskHelloLen || c.mask == nil {
		return false
	}
	switch {
	case !c.isClient && [maskHelloLen]byte(payload) == maskHello:
		// ack in the clear-protected form, then mask everything after it
		if _, err := c.Write(maskAck[:]); err == nil {
			c.recvROC = rocTracker{}
			c.recvMasked.Store(true)
			c.sendMasked.Store(true)
		}
		return true
	case c.isClient && [maskHelloLen]byte(payload) == maskAck:
		c.recvROC = rocTracker{}
		c.recvMasked.Store(true)
		c.sendMasked.Store(true)
		return true
	}
	_ = seq
	return false
}

// Write wraps b in an RTP packet, encrypts (or masks) it, and sends it to the remote
func (c *srtpConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seq, ts := c.seq, c.ts
	index := uint64(c.roc)<<16 | uint64(seq)
	c.seq++
	if c.seq == 0 {
		c.roc++
	}
	c.ts += uint32(len(b))

	buf := c.wbuf[:srtpHeaderLen]
	buf[0] = 0x80
	buf[1] = srtpPayloadType
	binary.BigEndian.PutUint16(buf[2:], seq)
	binary.BigEndian.PutUint32(buf[4:], ts)
	binary.BigEndian.PutUint32(buf[8:], c.ssrc)
	buf = append(buf, b...)

	var out []byte
	if c.sendMasked.Load() {
		c.mask.maskInPlace(c.ssrc, index, buf[srtpHeaderLen:])
		buf = append(buf, zeroTag[:srtpTagLen]...)
		c.mask.fillTag(buf[len(buf)-srtpTagLen:])
		out = buf
	} else {
		enc, err := c.encCtx.EncryptRTP(c.ebuf[:0], buf, nil)
		if err != nil {
			return 0, fmt.Errorf("srtp encrypt failed: %w", err)
		}
		c.ebuf = enc[:0]
		out = enc
	}
	c.wbuf = buf[:0]

	if _, err := c.raw.WriteTo(out, c.remote); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close shuts down the SRTP connection and any associated resources
func (c *srtpConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.dl.close()
		close(c.closed)
		if c.onClose != nil {
			c.onClose()
		}
		if c.dtlsConn != nil {
			err = c.dtlsConn.Close()
		}
		if c.underlay != nil {
			err = errors.Join(err, c.underlay.Close())
		}
	})
	return err
}

// LocalAddr returns the local address of the underlying conn
func (c *srtpConn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// RemoteAddr returns the remote peer address
func (c *srtpConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets both the read and write deadline
func (c *srtpConn) SetDeadline(t time.Time) error { c.dl.set(t); return nil }

// SetReadDeadline sets the deadline for future Read calls
func (c *srtpConn) SetReadDeadline(t time.Time) error { c.dl.set(t); return nil }

// SetWriteDeadline is a stub which does nothing since UDP is non-blocking
func (c *srtpConn) SetWriteDeadline(_ time.Time) error { return nil }

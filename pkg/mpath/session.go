// Package mpath is a multipath reliable transport: one session striped across many lossy,
// individually rate-policed packet paths. Each path has its own sequence numbers, ACKs,
// RTT estimate, loss detection and pacer; reliable data carries a session-level sequence
// number and is reassembled at the receiver, so reordering between paths never causes
// retransmissions. Unreliable datagrams bypass reassembly.
package mpath

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// Config tunes a session; zero fields take defaults
type Config struct {
	MaxPacketSize int           // bytes handed to a path conn per packet, including mpath overhead
	InitialRate   float64       // per-path pacing rate before any delivery samples, bytes/sec
	MinRate       float64       // per-path pacing floor while a path is alive
	MaxRate       float64       // per-path pacing ceiling, 0 for none
	InitialRTT    time.Duration // RTT assumed before the first sample
	MinRound      time.Duration // shortest pacing-gain phase
	MinPTO        time.Duration // floor for the tail-loss probe timeout
	MaxAckDelay   time.Duration // longest an ACK may be delayed
	PacingBurst   time.Duration // pacer credit kept after idle, absorbs timer granularity
	QueueHorizon  time.Duration // how far ahead a path's pacer may be booked before it stops taking packets
	LossThreshold float64       // per-epoch loss fraction that caps a path's rate
	LossEpoch     time.Duration // shortest loss-measurement epoch
	DeadTimeout   time.Duration // ACK silence after which a path is declared dead
	ProbeInterval time.Duration // probe period on a dead path
	KeepAlive     time.Duration // idle period after which a path is pinged
	PathExpiry    time.Duration // how long a dead path is kept before its conn is closed
	Grace         time.Duration // how long a session survives with no live path
	RecvWindow    int           // receive window in segments
	SendBuffer    int           // bytes buffered by Write before it blocks
	DatagramQueue int           // queued outgoing datagram packets before the oldest is dropped
	Logger        *slog.Logger
}

func (c *Config) withDefaults() *Config {
	out := *c
	def := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	if out.MaxPacketSize <= 0 {
		out.MaxPacketSize = 1380
	}
	if out.InitialRate <= 0 {
		out.InitialRate = 180 * 1024
	}
	if out.MinRate <= 0 {
		out.MinRate = 16 * 1024
	}
	def(&out.InitialRTT, 300*time.Millisecond)
	def(&out.MinRound, 100*time.Millisecond)
	def(&out.MinPTO, 30*time.Millisecond)
	def(&out.MaxAckDelay, 5*time.Millisecond)
	def(&out.PacingBurst, 5*time.Millisecond)
	def(&out.QueueHorizon, 20*time.Millisecond)
	if out.LossThreshold <= 0 {
		out.LossThreshold = 0.02
	}
	def(&out.LossEpoch, 500*time.Millisecond)
	def(&out.DeadTimeout, 1500*time.Millisecond)
	def(&out.ProbeInterval, 300*time.Millisecond)
	def(&out.KeepAlive, time.Second)
	def(&out.PathExpiry, 10*time.Second)
	def(&out.Grace, 3*time.Minute)
	if out.RecvWindow <= 0 {
		out.RecvWindow = 4096
	}
	if out.SendBuffer <= 0 {
		out.SendBuffer = 1 << 20
	}
	if out.DatagramQueue <= 0 {
		out.DatagramQueue = 256
	}
	if out.Logger == nil {
		out.Logger = slog.Default()
	}
	return &out
}

// plaintext layout: flags | window limit u32 | [path seq u32] | [ack] | [conn seq u32 | data] | [frag hdr | dgram]
const (
	fData  byte = 1 << 0
	fDgram byte = 1 << 1
	fPing  byte = 1 << 2
	fAck   byte = 1 << 3
	fClose byte = 1 << 4

	fEliciting = fData | fDgram | fPing

	hdrLen     = 1 + 4
	ackLen     = 4 + 2 + 8 // largest, delay (100 µs units), bitmap
	dataHdrLen = 4
	fragHdrLen = 3 // fragment id u16, index<<4 | count
	maxFrags   = 15
)

// ErrClosed is returned after the session has been closed
var ErrClosed = errors.New("mpath: session closed")

// ErrGraceExpired is the close reason when no path came back within Config.Grace
var ErrGraceExpired = errors.New("mpath: no live path within the grace period")

// segment is one chunk of the reliable byte stream
type segment struct {
	seq    uint32
	data   []byte
	acked  bool
	queued bool // waiting in the retransmit queue
	sent   bool // sent at least once
}

// fragBuf reassembles one fragmented datagram
type fragBuf struct {
	parts [][]byte
	got   int
	at    time.Time
}

// SessionStats are session-wide counters
type SessionStats struct {
	SegmentsSent    uint64 // reliable segments sent, including retransmissions
	Retransmits     uint64 // reliable segment retransmissions
	DupSegments     uint64 // received segments already delivered: spurious retransmissions by the peer
	DatagramsSent   uint64
	DatagramsDrop   uint64 // dropped locally because the queue was full
	DatagramsRecvd  uint64
	DatagramsInDrop uint64 // dropped because the reader fell behind
	Paths           []PathStats
}

// outPkt is a plaintext ready to be sealed and written to a path
type outPkt struct {
	p     *path
	plain []byte
}

// Session is one multipath connection. It implements io.ReadWriteCloser for the reliable stream.
type Session struct {
	cfg      *Config
	keys     *keys
	id       []byte
	isClient bool
	log      *slog.Logger

	mu         sync.Mutex
	sendCond   *sync.Cond
	readCond   *sync.Cond
	paths      []*path
	nextPathID int

	// reliable send side
	sendNext     uint32
	queue        []*segment // never sent, in order
	retrans      []*segment
	unacked      map[uint32]*segment
	sendBuffered int
	peerLimit    uint32

	// reliable receive side
	recvCum       uint32
	ooo           map[uint32][]byte
	readQ         [][]byte
	advertised    uint32
	windowPending bool

	// datagrams
	dgOut    [][]byte
	dgIn     chan []byte
	dgNextID uint16
	frags    map[uint16]*fragBuf

	stats SessionStats

	lastAlive     time.Time
	lastHouse     time.Time
	notifyCh      chan struct{}
	closed        chan struct{}
	closeOnce     sync.Once
	closeErr      error
	onPathDead    func(net.Conn)
	onPathRemoved func(net.Conn)

	handshakeReply func([]byte) []byte // server: answers handshake retransmissions on bound paths
}

func newSession(cfg *Config, k *keys, id []byte, isClient bool) *Session {
	cfg = cfg.withDefaults()
	s := &Session{
		cfg: cfg, keys: k, id: id, isClient: isClient, log: cfg.Logger,
		unacked:   make(map[uint32]*segment),
		ooo:       make(map[uint32][]byte),
		peerLimit: uint32(cfg.RecvWindow),
		dgIn:      make(chan []byte, 1024),
		frags:     make(map[uint16]*fragBuf),
		notifyCh:  make(chan struct{}, 1),
		closed:    make(chan struct{}),
		lastAlive: time.Now(),
	}
	s.advertised = uint32(cfg.RecvWindow)
	s.sendCond = sync.NewCond(&s.mu)
	s.readCond = sync.NewCond(&s.mu)
	go s.sendLoop()
	return s
}

// ID returns the session identifier
func (s *Session) ID() []byte { return s.id }

// Done is closed when the session ends
func (s *Session) Done() <-chan struct{} { return s.closed }

// Err returns why the session ended
func (s *Session) Err() error {
	select {
	case <-s.closed:
		return s.closeErr
	default:
		return nil
	}
}

func (s *Session) mss() int { return s.cfg.MaxPacketSize - sealOverhead - hdrLen - 4 - dataHdrLen }

func (s *Session) notify() {
	select {
	case s.notifyCh <- struct{}{}:
	default:
	}
}

// attach registers a handshaken conn as a path and starts reading it
func (s *Session) attach(conn net.Conn) *path {
	s.mu.Lock()
	p := newPath(s.nextPathID, conn, s.cfg, time.Now())
	s.nextPathID++
	s.paths = append(s.paths, p)
	alive := s.aliveCount()
	s.mu.Unlock()
	s.log.Debug("mpath path attached", "path", p.id, "alive", alive)
	go s.readLoop(p)
	s.notify()
	return p
}

func (s *Session) aliveCount() int {
	n := 0
	for _, p := range s.paths {
		if !p.dead && !p.removed {
			n++
		}
	}
	return n
}

// AlivePaths returns the number of paths currently carrying traffic
func (s *Session) AlivePaths() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aliveCount()
}

// SetPathHandlers sets callbacks for a path declared dead (no ACKs) and a path removed (conn failed)
func (s *Session) SetPathHandlers(dead, removed func(net.Conn)) {
	s.mu.Lock()
	s.onPathDead, s.onPathRemoved = dead, removed
	s.mu.Unlock()
}

// removePathLocked drops a path and requeues everything it had in flight
func (s *Session) removePathLocked(p *path) {
	if p.removed {
		return
	}
	p.removed = true
	s.requeueLocked(p.takeAll())
	for i, q := range s.paths {
		if q == p {
			s.paths = append(s.paths[:i], s.paths[i+1:]...)
			break
		}
	}
	if cb := s.onPathRemoved; cb != nil {
		go cb(p.conn)
	}
	s.log.Debug("mpath path removed", "path", p.id, "alive", s.aliveCount())
	s.notify()
}

func (s *Session) requeueLocked(lost []*sentPkt) {
	for _, sp := range lost {
		seg := sp.seg
		if seg == nil || seg.acked || seg.queued {
			continue
		}
		seg.queued = true
		s.retrans = append(s.retrans, seg)
	}
}

// Write queues bytes on the reliable stream, blocking while the send buffer is full
func (s *Session) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mss := s.mss()
	n := 0
	for len(b) > 0 {
		for s.sendBuffered >= s.cfg.SendBuffer && !s.isClosed() {
			s.sendCond.Wait()
		}
		if s.isClosed() {
			return n, ErrClosed
		}
		// coalesce into the unsent tail segment
		if k := len(s.queue); k > 0 && len(s.queue[k-1].data) < mss {
			last := s.queue[k-1]
			c := min(mss-len(last.data), len(b))
			last.data = append(last.data, b[:c]...)
			b, n, s.sendBuffered = b[c:], n+c, s.sendBuffered+c
			continue
		}
		c := min(mss, len(b))
		data := make([]byte, c, mss)
		copy(data, b)
		seg := &segment{seq: s.sendNext, data: data}
		s.sendNext++
		s.queue = append(s.queue, seg)
		s.unacked[seg.seq] = seg
		b, n, s.sendBuffered = b[c:], n+c, s.sendBuffered+c
	}
	s.notify()
	return n, nil
}

// Read reads in-order bytes from the reliable stream
func (s *Session) Read(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.readQ) == 0 {
		if s.isClosed() {
			return 0, io.EOF
		}
		s.readCond.Wait()
	}
	n := 0
	for n < len(b) && len(s.readQ) > 0 {
		c := copy(b[n:], s.readQ[0])
		n += c
		if c == len(s.readQ[0]) {
			s.readQ[0] = nil
			s.readQ = s.readQ[1:]
		} else {
			s.readQ[0] = s.readQ[0][c:]
		}
	}
	// open the window once a quarter of it has been consumed
	if s.limitLocked()-s.advertised >= uint32(s.cfg.RecvWindow/4) {
		s.windowPending = true
		s.notify()
	}
	return n, nil
}

func (s *Session) limitLocked() uint32 {
	return s.recvCum + uint32(s.cfg.RecvWindow) - uint32(len(s.readQ))
}

// SendDatagram queues an unreliable datagram, fragmenting it if needed
func (s *Session) SendDatagram(b []byte) error {
	maxFrag := s.mss() + dataHdrLen - fragHdrLen
	cnt := (len(b) + maxFrag - 1) / maxFrag
	if cnt == 0 {
		cnt = 1
	}
	if cnt > maxFrags {
		return errors.New("mpath: datagram too large")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed() {
		return ErrClosed
	}
	id := s.dgNextID
	s.dgNextID++
	for i := 0; i < cnt; i++ {
		part := b[i*maxFrag : min((i+1)*maxFrag, len(b))]
		f := make([]byte, fragHdrLen+len(part))
		binary.BigEndian.PutUint16(f, id)
		f[2] = byte(i<<4 | cnt)
		copy(f[fragHdrLen:], part)
		if len(s.dgOut) >= s.cfg.DatagramQueue {
			s.dgOut[0] = nil
			s.dgOut = s.dgOut[1:]
			s.stats.DatagramsDrop++
		}
		s.dgOut = append(s.dgOut, f)
	}
	s.notify()
	return nil
}

// ReceiveDatagram returns the next datagram
func (s *Session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case d := <-s.dgIn:
		return d, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, ErrClosed
	}
}

func (s *Session) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// Close ends the session, telling the peer, and closes every path conn
func (s *Session) Close() error {
	s.closeWith(ErrClosed, true)
	return nil
}

func (s *Session) closeWith(reason error, tellPeer bool) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closeErr = reason
		paths := append([]*path(nil), s.paths...)
		limit := s.limitLocked()
		close(s.closed)
		s.sendCond.Broadcast()
		s.readCond.Broadcast()
		s.mu.Unlock()
		for _, p := range paths {
			if tellPeer {
				plain := make([]byte, hdrLen)
				plain[0] = fClose
				binary.BigEndian.PutUint32(plain[1:], limit)
				s.writePath(p, plain)
			}
			_ = p.conn.Close()
		}
	})
}

// Stats returns a snapshot of the session counters
func (s *Session) Stats() SessionStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	now := time.Now()
	out.Paths = make([]PathStats, 0, len(s.paths))
	for _, p := range s.paths {
		ps := p.stats
		ps.PacingRate = p.rate(now)
		ps.SmoothedRTT = p.srtt
		ps.Dead = p.dead
		out.Paths = append(out.Paths, ps)
	}
	return out
}

// writePath seals and writes one packet
func (s *Session) writePath(p *path, plain []byte) {
	pkt := s.keys.send.seal(make([]byte, 0, len(plain)+sealOverhead), plain)
	p.writeMu.Lock()
	_, err := p.conn.Write(pkt)
	p.writeMu.Unlock()
	if err != nil && !s.isClosed() {
		s.mu.Lock()
		s.removePathLocked(p)
		s.mu.Unlock()
		_ = p.conn.Close()
	}
}

// readLoop receives packets from one path until its conn fails
func (s *Session) readLoop(p *path) {
	buf := make([]byte, 65536)
	plainBuf := make([]byte, 0, 65536)
	for {
		n, err := p.conn.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			s.mu.Lock()
			s.removePathLocked(p)
			s.mu.Unlock()
			_ = p.conn.Close()
			return
		}
		if n == 0 {
			continue
		}
		if buf[0] != 0 {
			// late handshake retransmission; a reject means the server lost our session
			if buf[0] == kindReject && n >= 3 && buf[2] == rejectUnknown && s.isClient {
				s.closeWith(ErrUnknownSession, false)
				return
			}
			if s.handshakeReply != nil {
				if r := s.handshakeReply(buf[:n]); r != nil {
					p.writeMu.Lock()
					_, _ = p.conn.Write(r)
					p.writeMu.Unlock()
				}
			}
			continue
		}
		plain, err := s.keys.recv.open(plainBuf[:0], buf[:n])
		if err != nil {
			continue
		}
		if ack := s.handlePacket(p, plain); ack != nil {
			s.writePath(p, ack)
		}
	}
}

// handlePacket processes one decrypted packet and returns an ACK to send immediately, if any
func (s *Session) handlePacket(p *path, b []byte) []byte {
	if len(b) < hdrLen {
		return nil
	}
	now := time.Now()
	flags := b[0]
	limit := binary.BigEndian.Uint32(b[1:])
	b = b[hdrLen:]

	s.mu.Lock()
	defer s.mu.Unlock()
	if p.removed {
		return nil
	}
	p.stats.PacketsRecvd++
	if int32(limit-s.peerLimit) > 0 {
		s.peerLimit = limit
		s.notify()
	}
	if flags&fClose != 0 {
		s.mu.Unlock()
		s.closeWith(ErrClosed, false)
		s.mu.Lock()
		return nil
	}

	var seq uint32
	eliciting := flags&fEliciting != 0
	if eliciting {
		if len(b) < 4 {
			return nil
		}
		seq = binary.BigEndian.Uint32(b)
		b = b[4:]
	}
	if flags&fAck != 0 {
		if len(b) < ackLen {
			return nil
		}
		largest := binary.BigEndian.Uint32(b)
		delay := time.Duration(binary.BigEndian.Uint16(b[4:])) * 100 * time.Microsecond
		bitmap := binary.BigEndian.Uint64(b[6:])
		b = b[ackLen:]
		s.onAckLocked(p, now, largest, delay, bitmap)
	}
	if !eliciting {
		return nil
	}

	inOrder := p.recvLargest < 0 || int64(seq) == p.recvLargest+1
	if p.onRecv(seq) {
		// path-level duplicate: still ACK so the sender stops resending
		return s.ackLocked(p, now)
	}
	if p.ackPending == 0 {
		p.ackFirstTime = now
	}
	p.ackPending++

	switch {
	case flags&fData != 0 && len(b) >= dataHdrLen:
		s.onDataLocked(binary.BigEndian.Uint32(b), b[dataHdrLen:])
	case flags&fDgram != 0 && len(b) >= fragHdrLen:
		s.onDatagramLocked(b, now)
	}

	if p.ackPending >= 2 || flags&fPing != 0 || !inOrder {
		return s.ackLocked(p, now)
	}
	s.notify() // the send loop flushes delayed ACKs
	return nil
}

func (s *Session) onAckLocked(p *path, now time.Time, largest uint32, delay time.Duration, bitmap uint64) {
	lost, acked, n := p.onAck(now, largest, delay, bitmap)
	for _, seg := range acked {
		if seg.acked {
			continue
		}
		seg.acked = true
		if _, ok := s.unacked[seg.seq]; ok {
			delete(s.unacked, seg.seq)
			s.sendBuffered -= len(seg.data)
		}
	}
	if len(acked) > 0 {
		s.sendCond.Broadcast()
	}
	s.requeueLocked(lost)
	if n > 0 && p.dead {
		p.dead = false
		p.ceiling = 0
		s.log.Debug("mpath path revived", "path", p.id, "alive", s.aliveCount())
	}
	if n > 0 || len(lost) > 0 {
		s.notify()
	}
}

func (s *Session) onDataLocked(seq uint32, data []byte) {
	if int32(seq-s.recvCum) < 0 {
		s.stats.DupSegments++
		return
	}
	if int32(seq-s.limitLocked()) >= 0 {
		return // beyond the advertised window; the peer must not do this
	}
	if seq != s.recvCum {
		if _, ok := s.ooo[seq]; ok {
			s.stats.DupSegments++
			return
		}
		s.ooo[seq] = append([]byte(nil), data...)
		return
	}
	s.readQ = append(s.readQ, append([]byte(nil), data...))
	s.recvCum++
	for {
		d, ok := s.ooo[s.recvCum]
		if !ok {
			break
		}
		delete(s.ooo, s.recvCum)
		s.readQ = append(s.readQ, d)
		s.recvCum++
	}
	s.readCond.Broadcast()
}

func (s *Session) onDatagramLocked(b []byte, now time.Time) {
	id := binary.BigEndian.Uint16(b)
	idx, cnt := int(b[2]>>4), int(b[2]&0x0f)
	payload := b[fragHdrLen:]
	if cnt == 0 || idx >= cnt {
		return
	}
	var whole []byte
	if cnt == 1 {
		whole = append([]byte(nil), payload...)
	} else {
		fb := s.frags[id]
		if fb == nil || len(fb.parts) != cnt {
			fb = &fragBuf{parts: make([][]byte, cnt), at: now}
			s.frags[id] = fb
		}
		if fb.parts[idx] != nil {
			return
		}
		fb.parts[idx] = append([]byte(nil), payload...)
		fb.got++
		if fb.got < cnt {
			return
		}
		delete(s.frags, id)
		for _, part := range fb.parts {
			whole = append(whole, part...)
		}
	}
	s.stats.DatagramsRecvd++
	select {
	case s.dgIn <- whole:
	default:
		s.stats.DatagramsInDrop++
	}
}

// ackLocked builds an ACK-only packet for path p
func (s *Session) ackLocked(p *path, now time.Time) []byte {
	if p.recvLargest < 0 {
		return nil
	}
	plain := make([]byte, hdrLen+ackLen)
	plain[0] = fAck
	limit := s.limitLocked()
	s.advertised = limit
	binary.BigEndian.PutUint32(plain[1:], limit)
	binary.BigEndian.PutUint32(plain[hdrLen:], uint32(p.recvLargest))
	delay := uint16(min(now.Sub(p.ackFirstTime)/(100*time.Microsecond), 65535))
	if p.ackPending == 0 {
		delay = 0
	}
	binary.BigEndian.PutUint16(plain[hdrLen+4:], delay)
	binary.BigEndian.PutUint64(plain[hdrLen+6:], p.recvBitmap)
	p.ackPending = 0
	p.ackFirstTime = time.Time{}
	return plain
}

// elicitingLocked builds an ack-eliciting packet on p, recording it in flight. Paced packets are
// queued on the path and returned as nil; unpaced ones (pings) are returned for immediate sending.
func (s *Session) elicitingLocked(p *path, now time.Time, flags byte, seg *segment, dgram []byte, appLimited bool) []byte {
	size := hdrLen + 4
	switch {
	case seg != nil:
		size += dataHdrLen + len(seg.data)
	case dgram != nil:
		size += len(dgram)
	}
	plain := make([]byte, size)
	plain[0] = flags
	limit := s.limitLocked()
	s.advertised = limit
	binary.BigEndian.PutUint32(plain[1:], limit)
	paced := flags&(fData|fDgram) != 0
	seq, due := p.onSend(now, size+sealOverhead, seg, appLimited, paced)
	binary.BigEndian.PutUint32(plain[hdrLen:], seq)
	switch {
	case seg != nil:
		binary.BigEndian.PutUint32(plain[hdrLen+4:], seg.seq)
		copy(plain[hdrLen+4+dataHdrLen:], seg.data)
	case dgram != nil:
		copy(plain[hdrLen+4:], dgram)
	}
	if paced {
		p.outq = append(p.outq, queued{due: due, plain: plain})
		return nil
	}
	return plain
}

// sendLoop is the single scheduler: it picks the next payload and the path that delivers it earliest
func (s *Session) sendLoop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var out []outPkt
	for {
		s.mu.Lock()
		if s.isClosed() {
			s.mu.Unlock()
			return
		}
		now := time.Now()
		out = out[:0]
		out = s.housekeepingLocked(now, out)
		var wait time.Duration
		out, wait = s.scheduleLocked(now, out)
		s.mu.Unlock()

		for i := range out {
			s.writePath(out[i].p, out[i].plain)
			out[i] = outPkt{}
		}
		if len(out) > 0 && wait == 0 {
			continue
		}
		if wait <= 0 || wait > 5*time.Millisecond {
			wait = 5 * time.Millisecond // housekeeping tick
		}
		timer.Reset(wait)
		select {
		case <-s.notifyCh:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		case <-s.closed:
			return
		}
	}
}

// housekeepingLocked handles delayed ACKs, timeouts, dead paths, probes and keepalives
func (s *Session) housekeepingLocked(now time.Time, out []outPkt) []outPkt {
	for _, p := range s.paths {
		if p.ackPending > 0 && now.Sub(p.ackFirstTime) >= s.cfg.MaxAckDelay {
			if a := s.ackLocked(p, now); a != nil {
				out = append(out, outPkt{p, a})
			}
		}
	}
	if s.windowPending {
		s.windowPending = false
		if p := s.bestPathLocked(now, false); p != nil {
			if a := s.ackLocked(p, now); a != nil {
				out = append(out, outPkt{p, a})
			} else {
				out = append(out, outPkt{p, s.elicitingLocked(p, now, fPing, nil, nil, true)})
			}
		}
	}
	if now.Sub(s.lastHouse) < 5*time.Millisecond {
		return out
	}
	s.lastHouse = now

	var expired []*path
	for _, p := range s.paths {
		if !p.dead {
			if lost := p.takeTimedOut(now); len(lost) > 0 {
				s.requeueLocked(lost)
				out = append(out, outPkt{p, s.elicitingLocked(p, now, fPing, nil, nil, true)})
			}
			if !p.waitingSince.IsZero() && now.Sub(p.waitingSince) > s.cfg.DeadTimeout {
				p.dead, p.deadSince = true, now
				s.requeueLocked(p.takeAll())
				s.log.Debug("mpath path dead", "path", p.id, "alive", s.aliveCount())
				if cb := s.onPathDead; cb != nil {
					go cb(p.conn)
				}
			} else if now.Sub(p.lastEliciting) > s.cfg.KeepAlive {
				out = append(out, outPkt{p, s.elicitingLocked(p, now, fPing, nil, nil, true)})
			}
		}
		if p.dead {
			if now.Sub(p.deadSince) > s.cfg.PathExpiry {
				expired = append(expired, p)
				continue
			}
			p.takeTimedOut(now)
			if now.Sub(p.lastProbe) > s.cfg.ProbeInterval {
				p.lastProbe = now
				p.waitingSince = time.Time{}
				out = append(out, outPkt{p, s.elicitingLocked(p, now, fPing, nil, nil, true)})
				p.waitingSince = time.Time{} // probes must not re-trigger death bookkeeping
			}
		}
	}
	for _, p := range expired {
		s.removePathLocked(p)
		go func(c net.Conn) { _ = c.Close() }(p.conn)
	}

	// expire stale datagram fragments
	for id, fb := range s.frags {
		if now.Sub(fb.at) > 2*time.Second {
			delete(s.frags, id)
		}
	}

	if s.aliveCount() > 0 {
		s.lastAlive = now
	} else if now.Sub(s.lastAlive) > s.cfg.Grace {
		go s.closeWith(ErrGraceExpired, false)
	}
	return out
}

// bestPathLocked returns the live path with the earliest estimated arrival. With forData, only
// paths whose pacer backlog is under the queue horizon and whose window has room qualify.
func (s *Session) bestPathLocked(now time.Time, forData bool) *path {
	var best *path
	var bestAt time.Time
	for _, p := range s.paths {
		if p.dead || p.removed || (forData && (!p.usable(now) || p.backlog(now) > s.cfg.QueueHorizon)) {
			continue
		}
		at := p.arrival(now)
		if best == nil || at.Before(bestAt) {
			best, bestAt = p, at
		}
	}
	return best
}

// nextPayloadLocked peeks at the next thing to send: a retransmission, a datagram or new data
func (s *Session) nextPayloadLocked() (seg *segment, dgram []byte, ok bool) {
	for len(s.retrans) > 0 && s.retrans[0].acked {
		s.retrans[0].queued = false
		s.retrans[0] = nil
		s.retrans = s.retrans[1:]
	}
	if len(s.retrans) > 0 {
		return s.retrans[0], nil, true
	}
	if len(s.dgOut) > 0 {
		return nil, s.dgOut[0], true
	}
	if len(s.queue) > 0 && int32(s.queue[0].seq-s.peerLimit) < 0 {
		return s.queue[0], nil, true
	}
	return nil, nil, false
}

const maxBatch = 256

// scheduleLocked commits payloads to paths, earliest arrival first, then emits every queued
// packet whose pacing time has come. It returns how long until the next queued packet is due.
func (s *Session) scheduleLocked(now time.Time, out []outPkt) ([]outPkt, time.Duration) {
	for n := 0; n < maxBatch; n++ {
		seg, dgram, ok := s.nextPayloadLocked()
		if !ok {
			break
		}
		p := s.bestPathLocked(now, true)
		if p == nil {
			break // every path is booked or window-limited; ACKs and pacing will wake us
		}
		appLimited := len(s.queue) <= 1 && len(s.retrans) == 0
		switch {
		case dgram != nil:
			s.dgOut[0] = nil
			s.dgOut = s.dgOut[1:]
			s.stats.DatagramsSent++
			s.elicitingLocked(p, now, fDgram, nil, dgram, appLimited)
		case seg.queued:
			seg.queued = false
			s.retrans[0] = nil
			s.retrans = s.retrans[1:]
			s.stats.Retransmits++
			s.stats.SegmentsSent++
			s.elicitingLocked(p, now, fData, seg, nil, appLimited)
		default:
			s.queue[0] = nil
			s.queue = s.queue[1:]
			seg.sent = true
			s.stats.SegmentsSent++
			s.elicitingLocked(p, now, fData, seg, nil, appLimited)
		}
	}

	var wait time.Duration
	for _, p := range s.paths {
		i := 0
		for ; i < len(p.outq) && !p.outq[i].due.After(now); i++ {
			out = append(out, outPkt{p, p.outq[i].plain})
		}
		if i > 0 {
			clear(p.outq[:i])
			p.outq = p.outq[i:]
		}
		if len(p.outq) > 0 {
			if d := p.outq[0].due.Sub(now); wait == 0 || d < wait {
				wait = d
			}
		}
	}
	return out, wait
}

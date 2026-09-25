package connection

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrPeerDone is returned by a reconnectFn to signal that this peer slot should be removed
var ErrPeerDone = errors.New("peer: done")

const (
	peerMaxPacket       = muxMaxPacket + 2 // maximum packet size read from a peer connection; must hold a full mux frame
	peerReconnectInit   = 1 * time.Second  // initial back-off delay between failed peer dial attempts
	peerReconnectMax    = 10 * time.Second // maximum back-off delay between failed peer dial attempts
	peerStableAfter     = 10 * time.Second // how long a peer must stay online before its next drop is redialed immediately
	peerIncomingBufSize = 1024             // channel buffer size for packets arriving from all peers
	peerWriteSendBuf    = 256              // per-peer outbound write queue depth
)

// SessionGrace is how long a session waits out an outage before giving up and starting over with fresh credentials
// It stays below the 5 minute TURN permission lifetime: past that point the relay has forgotten us anyway
const SessionGrace = 3 * time.Minute

// peerEntry holds one live connection inside PeerConn
type peerEntry struct {
	mu        sync.Mutex
	conn      net.Conn
	connected atomic.Bool
	sendCh    chan []byte
}

// PeerConn aggregates multiple per-peer connections into one logical net.Conn
type PeerConn struct {
	mu       sync.RWMutex
	peers    []*peerEntry
	incoming chan []byte
	ctx      context.Context
	cancel   context.CancelFunc
	writeIdx atomic.Uint64
	closed   atomic.Bool
	allGone  atomic.Bool

	lastOnline atomic.Int64 // unix nanoseconds of the last moment any peer was online

	peerReady chan struct{}
	allGoneCh chan struct{}

	log *slog.Logger
}

// NewPeerConn creates an empty PeerConn derived from the given context
func NewPeerConn(ctx context.Context) *PeerConn {
	ctx, cancel := context.WithCancel(ctx)
	p := &PeerConn{
		incoming:  make(chan []byte, peerIncomingBufSize),
		peerReady: make(chan struct{}),
		allGoneCh: make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
		log:       slog.Default(),
	}
	p.lastOnline.Store(time.Now().UnixNano())
	return p
}

// AllPeersGone returns a channel that is closed once every peer slot has been lost
func (m *PeerConn) AllPeersGone() <-chan struct{} {
	return m.allGoneCh
}

// SetLogger sets the logger
func (m *PeerConn) SetLogger(l *slog.Logger) {
	if l == nil {
		l = slog.Default()
	}
	m.log = l
}

// AddPeer adds a peer connection and starts its read and write loops
func (m *PeerConn) AddPeer(dialFn func(context.Context, int) (net.Conn, error)) error {
	if m.closed.Load() {
		return errors.New("peer: conn is closed")
	}
	m.allGone.Store(false)

	entry := &peerEntry{
		sendCh: make(chan []byte, peerWriteSendBuf),
	}

	m.mu.Lock()
	idx := len(m.peers)
	m.peers = append(m.peers, entry)
	m.mu.Unlock()

	go m.peerWriteLoop(entry)
	go m.peerReadLoop(idx, entry, dialFn)
	return nil
}

// peerWriteLoop drains the per-peer send queue and writes each packet to the connection
func (m *PeerConn) peerWriteLoop(entry *peerEntry) {
	for {
		select {
		case pkt, ok := <-entry.sendCh:
			if !ok {
				return
			}
			if !entry.connected.Load() {
				continue
			}
			entry.mu.Lock()
			conn := entry.conn
			entry.mu.Unlock()
			if conn != nil {
				_, _ = conn.Write(pkt)
			}
		case <-m.ctx.Done():
			return
		}
	}
}

// peerReadLoop reads packets from one peer and feeds them into the incoming channel
// A peer that drops is redialed in place, reusing the dial function's TURN credentials: the relay keeps the
// allocation alive server-side, so riding out an outage costs one new allocation rather than the whole session
func (m *PeerConn) peerReadLoop(idx int, entry *peerEntry, dialFn func(context.Context, int) (net.Conn, error)) {
	buf := make([]byte, peerMaxPacket)
	delay := time.Duration(0)

	for {
		onlineAt, ok := m.dialPeer(idx, entry, dialFn, &delay)
		if !ok {
			return
		}

		for {
			entry.mu.Lock()
			conn := entry.conn
			entry.mu.Unlock()

			n, err := conn.Read(buf)
			if err == nil && n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				select {
				case m.incoming <- pkt:
				case <-m.ctx.Done():
					return
				}
				continue
			}

			select {
			case <-m.ctx.Done():
				return
			default:
			}

			if err == nil {
				continue
			}

			entry.connected.Store(false)
			_ = conn.Close()
			m.lastOnline.Store(time.Now().UnixNano())
			m.log.Info("peer offline", "peer_idx", idx, "online", m.countOnline(), "total", m.totalSlots(), "error", err)

			// a peer that flaps right after connecting keeps its growing back-off instead of redialing at once
			if time.Since(onlineAt) >= peerStableAfter {
				delay = 0
			}
			break
		}
	}
}

// dialPeer dials the peer slot until it is online, reporting when it came online, or false once the slot is finished
func (m *PeerConn) dialPeer(idx int, entry *peerEntry, dialFn func(context.Context, int) (net.Conn, error), delay *time.Duration) (time.Time, bool) {
	for {
		if *delay > 0 {
			select {
			case <-m.ctx.Done():
				return time.Time{}, false
			case <-time.After(*delay):
			}
		} else if m.ctx.Err() != nil {
			return time.Time{}, false
		}

		newConn, err := dialFn(m.ctx, idx)
		if err == nil {
			entry.mu.Lock()
			entry.conn = newConn
			entry.mu.Unlock()
			if m.ctx.Err() != nil {
				_ = newConn.Close()
				return time.Time{}, false
			}
			entry.connected.Store(true)
			m.lastOnline.Store(time.Now().UnixNano())

			select {
			case <-m.peerReady:
			default:
				close(m.peerReady)
			}

			m.log.Info("peer online", "peer_idx", idx, "online", m.countOnline(), "total", m.totalSlots())
			return time.Now(), true
		}

		if errors.Is(err, ErrPeerDone) {
			m.log.Info("peer done, removing slot", "peer_idx", idx)
			m.removePeer(idx)
			return time.Time{}, false
		}

		if *delay == 0 {
			*delay = peerReconnectInit
		} else {
			*delay = min(*delay*2, peerReconnectMax)
		}
		m.log.Warn("peer dial failed", "peer_idx", idx, "delay", *delay, "error", err)

		if m.countOnline() == 0 && time.Since(time.Unix(0, m.lastOnline.Load())) > SessionGrace {
			m.log.Warn("no peer came back within the grace period", "grace", SessionGrace)
			m.notifyAllPeersGone()
			return time.Time{}, false
		}
	}
}

// countOnline returns the number of currently connected peer slots
func (m *PeerConn) countOnline() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, p := range m.peers {
		if p != nil && p.connected.Load() {
			n++
		}
	}
	return n
}

// totalSlots returns the total number of peer slots, including disconnected ones
func (m *PeerConn) totalSlots() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

// removePeer removes the peer at idx and cancels the conn if all peers are gone
func (m *PeerConn) removePeer(idx int) {
	m.mu.Lock()
	if idx < len(m.peers) {
		m.peers[idx] = nil
	}
	m.mu.Unlock()

	if m.countOnline() == 0 {
		m.lastOnline.Store(time.Now().UnixNano())
		m.scheduleAllGone(SessionGrace)
	}
}

// scheduleAllGone ends the conn once no peer has been online for SessionGrace, giving a dropped client time to rejoin
func (m *PeerConn) scheduleAllGone(wait time.Duration) {
	time.AfterFunc(wait, func() {
		if m.ctx.Err() != nil || m.countOnline() > 0 {
			return
		}
		if left := SessionGrace - time.Since(time.Unix(0, m.lastOnline.Load())); left > 0 {
			m.scheduleAllGone(left)
			return
		}
		m.notifyAllPeersGone()
	})
}

// notifyAllPeersGone closes the peer context and the AllPeersGone channel, once
func (m *PeerConn) notifyAllPeersGone() {
	if !m.allGone.CompareAndSwap(false, true) {
		return
	}
	m.log.Debug("all peers disconnected, closing peer conn")
	m.cancel()
	close(m.allGoneCh)
}

// Read blocks until a packet arrives from any peer
func (m *PeerConn) Read(p []byte) (int, error) {
	select {
	case pkt, ok := <-m.incoming:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, pkt)
		return n, nil
	case <-m.ctx.Done():
		return 0, io.EOF
	}
}

// Write enqueues one packet to the next live peer's send channel in round-robin order
func (m *PeerConn) Write(p []byte) (int, error) {
	m.mu.RLock()
	peers := m.peers
	m.mu.RUnlock()

	total := uint64(len(peers))
	if total == 0 {
		return 0, errors.New("peer: no peers")
	}

	start := m.writeIdx.Add(1) - 1
	buf := make([]byte, len(p))
	copy(buf, p)

	for i := uint64(0); i < total; i++ {
		entry := peers[(start+i)%total]
		if entry == nil || !entry.connected.Load() {
			continue
		}
		select {
		case entry.sendCh <- buf:
			return len(p), nil
		default:
		}
	}

	for i := uint64(0); i < total; i++ {
		entry := peers[(start+i)%total]
		if entry == nil || !entry.connected.Load() {
			continue
		}
		select {
		case entry.sendCh <- buf:
			return len(p), nil
		case <-m.ctx.Done():
			return 0, io.EOF
		}
	}

	select {
	case <-m.peerReady:
		// every peer is down mid-outage: drop like a lossy link would and let the layers above retransmit
		return len(p), nil
	case <-m.ctx.Done():
		return 0, io.EOF
	}
}

// RemoteAddr returns a dummy remote address
func (m *PeerConn) RemoteAddr() net.Addr { return peerDummyAddr{} }

// Close shuts down all peer connections
func (m *PeerConn) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	m.cancel()
	m.mu.RLock()
	peers := m.peers
	m.mu.RUnlock()
	for _, entry := range peers {
		if entry == nil {
			continue
		}
		entry.mu.Lock()
		conn := entry.conn
		entry.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
	}
	return nil
}

// LocalAddr returns a dummy local address
func (m *PeerConn) LocalAddr() net.Addr { return peerDummyAddr{} }

// SetDeadline is a no-op
func (m *PeerConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op
func (m *PeerConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op
func (m *PeerConn) SetWriteDeadline(t time.Time) error { return nil }

// peerDummyAddr is a placeholder net.Addr for PeerConn
type peerDummyAddr struct{}

// Network returns the network name for this dummy address
func (peerDummyAddr) Network() string { return "peer" }

// String returns the string form of this dummy address
func (peerDummyAddr) String() string { return "peer" }

// OneShotDial returns a dial function that hands out conn once, then reports ErrPeerDone since a dropped inbound conn cannot be redialed
func OneShotDial(conn net.Conn) func(context.Context, int) (net.Conn, error) {
	var used atomic.Bool
	return func(context.Context, int) (net.Conn, error) {
		if used.Swap(true) {
			return nil, ErrPeerDone
		}
		return conn, nil
	}
}

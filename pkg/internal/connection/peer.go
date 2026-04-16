package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theairblow/turnable/pkg/internal/protocol"
)

// ErrNeedFullReconnect is returned by a reconnectFn to signal that the peer session UUID is
// no longer valid on the server and the entire client session must be rebuilt from scratch
// (new primary handshake) rather than just reconnecting one peer as secondary.
var ErrNeedFullReconnect = errors.New("peer: full reconnect needed")

const (
	peerHandshakeTimeout = 10 * time.Second // peerHandshakeTimeout is the maximum time allowed for the peer handshake.

	peerMaxPacket       = 8192             // peerMaxPacket is the maximum packet size read from a peer connection.
	peerReconnectInit   = 5 * time.Second  // peerReconnectInit is the initial back-off delay before the first peer reconnect attempt.
	peerReconnectMax    = 8 * time.Second  // peerReconnectMax is the maximum back-off delay between peer reconnect attempts.
	peerQuotaBackoff    = 30 * time.Second // peerQuotaBackoff is the delay when TURN allocation quota is exhausted.
	peerIncomingBufSize = 256              // peerIncomingBufSize is the channel buffer size for packets arriving from all peers.
)

// peerEntry holds one live connection inside PeerConn.
type peerEntry struct {
	mu        sync.Mutex
	conn      io.ReadWriteCloser
	connected atomic.Bool
}

// PeerConn aggregates multiple per-peer connections into one logical net.PacketConn.
// Writes are round-robined across live peers; reads come from whichever peer delivers first.
type PeerConn struct {
	mu       sync.RWMutex
	peers    []*peerEntry
	incoming chan []byte
	ctx      context.Context
	cancel   context.CancelFunc
	writeIdx atomic.Uint64
	closed   atomic.Bool

	log             *slog.Logger // optional logger; nil means slog.Default()
	onFullReconnect func()       // called when a reconnect fn signals ErrNeedFullReconnect
	onAllPeersGone  func()       // called when every peer slot is removed (server: close transport)
}

// NewPeerConn creates an empty PeerConn. Add peers with AddPeer.
func NewPeerConn() *PeerConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &PeerConn{
		incoming: make(chan []byte, peerIncomingBufSize),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// SetOnFullReconnect registers a callback invoked when any reconnect function returns
// ErrNeedFullReconnect. The callback should initiate a fresh primary session (not just
// a secondary peer reconnect). It is called at most once per event; the peer loop exits
// immediately afterwards so the old PeerConn can be discarded.
func (m *PeerConn) SetOnFullReconnect(fn func()) {
	m.mu.Lock()
	m.onFullReconnect = fn
	m.mu.Unlock()
}

// SetOnAllPeersGone registers a callback invoked when the last peer slot is removed
func (m *PeerConn) SetOnAllPeersGone(fn func()) {
	m.mu.Lock()
	m.onAllPeersGone = fn
	m.mu.Unlock()
}

// SetLogger sets an optional logger; when nil, slog.Default() is used
func (m *PeerConn) SetLogger(l *slog.Logger) {
	m.mu.Lock()
	m.log = l
	m.mu.Unlock()
}

// logger returns the configured logger or slog.Default()
func (m *PeerConn) logger() *slog.Logger {
	m.mu.RLock()
	l := m.log
	m.mu.RUnlock()
	if l != nil {
		return l
	}
	return slog.Default()
}

// AddPeer adds a peer connection and starts its read loop. If reconnectFn is non-nil it is
// called on disconnect to get a replacement connection (with exponential back-off).
func (m *PeerConn) AddPeer(conn io.ReadWriteCloser, reconnectFn func(context.Context) (io.ReadWriteCloser, error)) error {
	if m.closed.Load() {
		return errors.New("peer: conn is closed")
	}
	entry := &peerEntry{conn: conn}
	entry.connected.Store(true)
	m.mu.Lock()
	idx := len(m.peers)
	m.peers = append(m.peers, entry)
	m.mu.Unlock()
	m.logger().Info("peer online", "peer_idx", idx, "online", m.countOnline(), "total", m.totalSlots())
	go m.peerReadLoop(idx, entry, reconnectFn)
	return nil
}

// peerReadLoop reads packets from one peer connection and feeds them into the incoming channel.
func (m *PeerConn) peerReadLoop(idx int, entry *peerEntry, reconnectFn func(context.Context) (io.ReadWriteCloser, error)) {
	buf := make([]byte, peerMaxPacket)
	delay := peerReconnectInit

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
			delay = peerReconnectInit
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
		m.logger().Info("peer offline", "peer_idx", idx, "online", m.countOnline(), "total", m.totalSlots(), "error", err)

		if reconnectFn == nil {
			m.removePeer(idx)
			return
		}

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(delay):
			}
			delay *= 2
			if delay > peerReconnectMax {
				delay = peerReconnectMax
			}

			newConn, err := reconnectFn(m.ctx)
			if err != nil {
				if errors.Is(err, ErrNeedFullReconnect) {
					m.logger().Info("peer needs full session reconnect", "peer_idx", idx)
					m.mu.RLock()
					fn := m.onFullReconnect
					m.mu.RUnlock()
					if fn != nil {
						fn()
					}
					return
				}
				if errors.Is(err, protocol.ErrQuotaReached) {
					m.logger().Warn("peer quota reached, backing off", "peer_idx", idx, "delay", peerQuotaBackoff)
					delay = peerQuotaBackoff
				}
				m.logger().Warn("peer reconnect failed", "peer_idx", idx, "online", m.countOnline(), "total", m.totalSlots(), "delay", delay, "error", err)
				continue
			}

			entry.mu.Lock()
			entry.conn = newConn
			entry.mu.Unlock()
			entry.connected.Store(true)
			delay = peerReconnectInit
			m.logger().Info("peer online", "peer_idx", idx, "online", m.countOnline(), "total", m.totalSlots())
			break
		}
	}
}

// countOnline returns the number of currently connected peer slots.
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

// totalSlots returns the total number of peer slots (including disconnected ones).
func (m *PeerConn) totalSlots() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

// removePeer removes the peer at idx and cancels the conn if all peers are gone.
func (m *PeerConn) removePeer(idx int) {
	m.mu.Lock()
	if idx < len(m.peers) {
		m.peers[idx] = nil
	}
	allGone := true
	for _, p := range m.peers {
		if p != nil {
			allGone = false
			break
		}
	}
	fn := m.onAllPeersGone
	m.mu.Unlock()

	if allGone {
		m.logger().Debug("all peers disconnected, closing peer conn")
		m.cancel()
		if fn != nil {
			fn()
		}
	}
}

// ReadFrom blocks until a packet arrives from any peer.
func (m *PeerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt, ok := <-m.incoming:
		if !ok {
			return 0, nil, io.EOF
		}
		n = copy(p, pkt)
		return n, peerDummyAddr{}, nil
	case <-m.ctx.Done():
		return 0, nil, io.EOF
	}
}

// WriteTo sends one packet to the next live peer in round-robin order.
func (m *PeerConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	m.mu.RLock()
	peers := m.peers
	m.mu.RUnlock()

	total := uint64(len(peers))
	if total == 0 {
		return 0, errors.New("peer: no peers")
	}

	start := m.writeIdx.Add(1) - 1
	for i := uint64(0); i < total; i++ {
		idx := (start + i) % total
		entry := peers[idx]
		if entry == nil || !entry.connected.Load() {
			continue
		}
		entry.mu.Lock()
		conn := entry.conn
		entry.mu.Unlock()
		if conn == nil {
			continue
		}
		n, err = conn.Write(p)
		if err == nil {
			return n, nil
		}
	}
	return 0, fmt.Errorf("peer: all peers failed: %w", err)
}

// Close shuts down all peer connections.
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

// LocalAddr returns a dummy local address for the peer conn.
func (m *PeerConn) LocalAddr() net.Addr { return peerDummyAddr{} }

// SetDeadline is a no-op; PeerConn does not support deadlines.
func (m *PeerConn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op; PeerConn does not support deadlines.
func (m *PeerConn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op; PeerConn does not support deadlines.
func (m *PeerConn) SetWriteDeadline(t time.Time) error { return nil }

// peerDummyAddr is a placeholder net.Addr used when no real address is available.
type peerDummyAddr struct{}

// Network returns the network name for the dummy address.
func (peerDummyAddr) Network() string { return "peer" }

// String returns the string representation of the dummy address.
func (peerDummyAddr) String() string { return "peer" }

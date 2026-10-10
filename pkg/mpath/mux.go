package mpath

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// Mux carries routed streams (smux over the reliable stream) and routed datagram flows on a session
type Mux struct {
	sess *Session      // multipath session underneath
	smux *smux.Session // stream multiplexer over the session's reliable stream

	mu       sync.Mutex               // guards flows
	flows    map[uint16]*DatagramFlow // datagram flows by ID
	nextFlow atomic.Uint32            // last locally assigned flow ID
	acceptDg chan *DatagramFlow       // flows first seen from the peer
	acceptSt chan *RoutedStream       // streams opened by the peer, with their route read
	done     chan struct{}            // closed once the mux ends
}

// RoutedStream is a reliable stream tagged with the route index it was opened for
type RoutedStream struct {
	*smux.Stream      // the underlying smux stream
	Route        byte // route index the stream was opened for
}

// datagram layout: flow id u16 | route u8 | payload
const dgHdrLen = 3

// smuxConfig returns the smux settings used on top of a session
func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.Version = 2
	c.KeepAliveDisabled = true // path liveness is handled by mpath
	c.MaxFrameSize = 32 * 1024
	c.MaxReceiveBuffer = 16 << 20
	c.MaxStreamBuffer = 4 << 20
	return c
}

// NewClientMux wraps a client session
func NewClientMux(sess *Session) (*Mux, error) {
	sm, err := smux.Client(sess, smuxConfig())
	if err != nil {
		return nil, err
	}
	return newMux(sess, sm), nil
}

// NewServerMux wraps a server session
func NewServerMux(sess *Session) (*Mux, error) {
	sm, err := smux.Server(sess, smuxConfig())
	if err != nil {
		return nil, err
	}
	return newMux(sess, sm), nil
}

// newMux starts the accept loops for a session and its smux
func newMux(sess *Session, sm *smux.Session) *Mux {
	m := &Mux{
		sess: sess, smux: sm,
		flows:    make(map[uint16]*DatagramFlow),
		acceptDg: make(chan *DatagramFlow, 64),
		acceptSt: make(chan *RoutedStream, 64),
		done:     make(chan struct{}),
	}
	go m.datagramLoop()
	go m.streamLoop()
	go func() {
		select {
		case <-sess.Done():
		case <-sm.CloseChan():
		}
		_ = m.Close()
	}()
	return m
}

// Session returns the underlying multipath session
func (m *Mux) Session() *Session { return m.sess }

// Done is closed when the mux ends
func (m *Mux) Done() <-chan struct{} { return m.done }

// OpenStream opens a reliable stream for a route
func (m *Mux) OpenStream(route byte) (*RoutedStream, error) {
	st, err := m.smux.OpenStream()
	if err != nil {
		return nil, err
	}
	if _, err := st.Write([]byte{route}); err != nil {
		_ = st.Close()
		return nil, err
	}
	return &RoutedStream{Stream: st, Route: route}, nil
}

// AcceptStream returns the next stream opened by the peer
func (m *Mux) AcceptStream(ctx context.Context) (*RoutedStream, error) {
	select {
	case st := <-m.acceptSt:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, ErrClosed
	}
}

// streamLoop accepts smux streams and reads each one's route header
func (m *Mux) streamLoop() {
	for {
		st, err := m.smux.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			var hdr [1]byte
			_ = st.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(st, hdr[:]); err != nil {
				_ = st.Close()
				return
			}
			_ = st.SetReadDeadline(time.Time{})
			select {
			case m.acceptSt <- &RoutedStream{Stream: st, Route: hdr[0]}:
			case <-m.done:
				_ = st.Close()
			}
		}()
	}
}

// OpenDatagramFlow opens an unreliable flow for a route
func (m *Mux) OpenDatagramFlow(route byte) *DatagramFlow {
	id := uint16(m.nextFlow.Add(1))
	f := m.newFlow(id, route)
	m.mu.Lock()
	m.flows[id] = f
	m.mu.Unlock()
	return f
}

// AcceptDatagramFlow returns the next flow first seen from the peer
func (m *Mux) AcceptDatagramFlow(ctx context.Context) (*DatagramFlow, error) {
	select {
	case f := <-m.acceptDg:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, ErrClosed
	}
}

// newFlow creates a flow without registering it
func (m *Mux) newFlow(id uint16, route byte) *DatagramFlow {
	return &DatagramFlow{mux: m, id: id, Route: route, in: make(chan []byte, 512), closed: make(chan struct{})}
}

// datagramLoop routes incoming datagrams to their flows, creating flows on first sight
func (m *Mux) datagramLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-m.done
		cancel()
	}()
	for {
		d, err := m.sess.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(d) < dgHdrLen {
			continue
		}
		id := binary.BigEndian.Uint16(d)
		m.mu.Lock()
		f := m.flows[id]
		isNew := false
		if f == nil {
			f = m.newFlow(id, d[2])
			m.flows[id] = f
			isNew = true
		}
		m.mu.Unlock()
		if isNew {
			select {
			case m.acceptDg <- f:
			default:
				continue // nobody is accepting; drop until they catch up
			}
		}
		select {
		case f.in <- d[dgHdrLen:]:
		default: // reader is behind: drop, as UDP would
		}
	}
}

// Close ends the mux and the session
func (m *Mux) Close() error {
	m.mu.Lock()
	select {
	case <-m.done:
		m.mu.Unlock()
		return nil
	default:
	}
	close(m.done)
	m.mu.Unlock()
	_ = m.smux.Close()
	return m.sess.Close()
}

// DatagramFlow is an unreliable, message-oriented net.Conn
type DatagramFlow struct {
	mux    *Mux          // owning mux
	id     uint16        // flow ID shared by both ends
	Route  byte          // route index the flow was opened for
	in     chan []byte   // received datagrams
	closed chan struct{} // closed by Close
	once   sync.Once     // guards Close

	deadline atomic.Pointer[time.Time] // read deadline
}

// ID returns the flow identifier
func (f *DatagramFlow) ID() uint16 { return f.id }

// Read returns one datagram
func (f *DatagramFlow) Read(b []byte) (int, error) {
	var timeout <-chan time.Time
	if dl := f.deadline.Load(); dl != nil && !dl.IsZero() {
		t := time.NewTimer(time.Until(*dl))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case d := <-f.in:
		return copy(b, d), nil
	case <-f.closed:
		return 0, io.EOF
	case <-f.mux.done:
		return 0, io.EOF
	case <-timeout:
		return 0, errDeadline
	}
}

// Write sends one datagram
func (f *DatagramFlow) Write(b []byte) (int, error) {
	select {
	case <-f.closed:
		return 0, net.ErrClosed
	default:
	}
	d := make([]byte, dgHdrLen+len(b))
	binary.BigEndian.PutUint16(d, f.id)
	d[2] = f.Route
	copy(d[dgHdrLen:], b)
	if err := f.mux.sess.SendDatagram(d); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close forgets the flow locally
func (f *DatagramFlow) Close() error {
	f.once.Do(func() {
		close(f.closed)
		f.mux.mu.Lock()
		delete(f.mux.flows, f.id)
		f.mux.mu.Unlock()
	})
	return nil
}

// deadlineErr is the timeout error returned when a read deadline passes
type deadlineErr struct{}

// Error returns the error message
func (deadlineErr) Error() string { return "i/o timeout" }

// Timeout reports that this is a timeout
func (deadlineErr) Timeout() bool { return true }

// Temporary reports that the operation may be retried
func (deadlineErr) Temporary() bool { return true }

// errDeadline is returned by DatagramFlow.Read after its deadline
var errDeadline net.Error = deadlineErr{}

// LocalAddr returns a placeholder address
func (f *DatagramFlow) LocalAddr() net.Addr { return flowAddr{} }

// RemoteAddr returns a placeholder address
func (f *DatagramFlow) RemoteAddr() net.Addr { return flowAddr{} }

// SetDeadline sets the read deadline
func (f *DatagramFlow) SetDeadline(t time.Time) error { return f.SetReadDeadline(t) }

// SetReadDeadline sets the read deadline
func (f *DatagramFlow) SetReadDeadline(t time.Time) error { f.deadline.Store(&t); return nil }

// SetWriteDeadline is a no-op
func (f *DatagramFlow) SetWriteDeadline(time.Time) error { return nil }

// flowAddr is a placeholder address for datagram flows
type flowAddr struct{}

// Network returns the network name for this placeholder address
func (flowAddr) Network() string { return "mpath" }

// String returns the string form of this placeholder address
func (flowAddr) String() string { return "mpath" }

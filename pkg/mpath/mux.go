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
	sess *Session
	smux *smux.Session

	mu       sync.Mutex
	flows    map[uint16]*DatagramFlow
	nextFlow atomic.Uint32
	acceptDg chan *DatagramFlow
	acceptSt chan *RoutedStream
	done     chan struct{}
}

// RoutedStream is a reliable stream tagged with the route index it was opened for
type RoutedStream struct {
	*smux.Stream
	Route byte
}

// datagram layout: flow id u16 | route u8 | payload
const dgHdrLen = 3

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

func (m *Mux) newFlow(id uint16, route byte) *DatagramFlow {
	return &DatagramFlow{mux: m, id: id, Route: route, in: make(chan []byte, 512), closed: make(chan struct{})}
}

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
	mux    *Mux
	id     uint16
	Route  byte
	in     chan []byte
	closed chan struct{}
	once   sync.Once

	deadline atomic.Pointer[time.Time]
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

type deadlineErr struct{}

func (deadlineErr) Error() string   { return "i/o timeout" }
func (deadlineErr) Timeout() bool   { return true }
func (deadlineErr) Temporary() bool { return true }

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

type flowAddr struct{}

func (flowAddr) Network() string { return "mpath" }
func (flowAddr) String() string  { return "mpath" }

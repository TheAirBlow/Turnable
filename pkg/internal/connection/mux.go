package connection

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theairblow/turnable/pkg/internal/transport"
)

// TODO: forward a logger with additional information prepended (e.g. session_id and peer_idx)

const (
	muxControlMagic        = "TMUX"
	muxControlVersion byte = 1

	muxControlTypeOpen       byte = 1
	muxControlTypePing       byte = 2
	muxControlTypePong       byte = 3
	muxControlTypeClose      byte = 4
	muxControlTypeDisconnect byte = 7

	muxFlowBufSize = 256
	muxMaxPacket   = 65535

	muxClientPingInterval = 1 * time.Second
	muxPingTimeout        = 5 * time.Second
)

// muxControlMessage is a control protocol message
type muxControlMessage struct {
	Type   byte
	FlowID uint16
}

// MuxChannel is one negotiated data flow
type MuxChannel struct {
	FlowID uint16
	Conn   net.Conn
}

// tinyMuxCore represents the shared core implementation of tinymux
type tinyMuxCore struct {
	conn   net.Conn
	flows  sync.Map
	nextID uint16
	nextMu sync.Mutex
	closed atomic.Bool
	done   chan struct{}
}

// newTinyMuxCore creates a new tinymux core
func newTinyMuxCore(conn net.Conn) *tinyMuxCore {
	m := &tinyMuxCore{
		conn:   conn,
		nextID: 1,
		done:   make(chan struct{}),
	}

	go m.readLoop()
	return m
}

// readLoop reads packets from the underlying connection and dispatches them to their flows
func (m *tinyMuxCore) readLoop() {
	defer func() {
		_ = m.Close()
	}()

	buf := make([]byte, muxMaxPacket+2)
	for {
		n, err := m.conn.Read(buf)
		if err != nil {
			return
		}
		if n < 2 {
			continue
		}

		flowID := binary.BigEndian.Uint16(buf[:2])
		payload := make([]byte, n-2)
		copy(payload, buf[2:n])

		if raw, ok := m.flows.Load(flowID); ok {
			if !raw.(*flowConn).deliver(payload) {
				slog.Debug("mux flow buffer got too congested", "flow_id", flowID)
			}
		}
	}
}

// createFlow creates a flow with the given ID
func (m *tinyMuxCore) createFlow(id uint16) *flowConn {
	fc := &flowConn{
		mux:      m,
		id:       id,
		incoming: make(chan []byte, muxFlowBufSize),
	}
	m.flows.Store(id, fc)
	return fc
}

// allocateFlow allocates the next flow ID and creates the flow
func (m *tinyMuxCore) allocateFlow() *flowConn {
	m.nextMu.Lock()
	id := m.nextID
	m.nextID++
	if m.nextID == 0 {
		m.nextID = 1
	}
	m.nextMu.Unlock()
	return m.createFlow(id)
}

// removeFlow removes a flow by ID
func (m *tinyMuxCore) removeFlow(id uint16) {
	m.flows.Delete(id)
}

// writePacket prepends the flow ID header and writes the payload to the underlying connection
func (m *tinyMuxCore) writePacket(flowID uint16, payload []byte) (int, error) {
	out := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(out, flowID)
	copy(out[2:], payload)
	_, err := m.conn.Write(out)
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

// Close closes the mux and underlying connection
func (m *tinyMuxCore) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}

	m.flows.Range(func(key, value any) bool {
		_ = value.(*flowConn).Close()
		return true
	})

	return m.conn.Close()
}

// flowConn represents a mux flow's net.Conn
type flowConn struct {
	mux       *tinyMuxCore
	id        uint16
	incoming  chan []byte
	readBuf   []byte
	closeOnce sync.Once
}

// Read reads the next chunk from the flow's receive buffer
func (f *flowConn) Read(p []byte) (int, error) {
	if len(f.readBuf) > 0 {
		n := copy(p, f.readBuf)
		f.readBuf = f.readBuf[n:]
		return n, nil
	}

	pkt, ok := <-f.incoming
	if !ok {
		return 0, io.EOF
	}

	n := copy(p, pkt)
	if n < len(pkt) {
		f.readBuf = pkt[n:]
	}

	return n, nil
}

// deliver safely sends payload into the flow's receive buffer
func (f *flowConn) deliver(payload []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	select {
	case f.incoming <- payload:
		return true
	default:
		return false
	}
}

// Write forwards the payload to the underlying mux connection under this flow's ID
func (f *flowConn) Write(p []byte) (int, error) {
	return f.mux.writePacket(f.id, p)
}

// Close removes this flow from the mux and closes it
func (f *flowConn) Close() error {
	f.mux.removeFlow(f.id)
	f.closeOnce.Do(func() { close(f.incoming) })
	return nil
}

// FlowID returns the flow identifier
func (f *flowConn) FlowID() uint16 { return f.id }

// LocalAddr returns the local address of the underlying mux connection
func (f *flowConn) LocalAddr() net.Addr { return f.mux.conn.LocalAddr() }

// RemoteAddr returns the remote address of the underlying mux connection
func (f *flowConn) RemoteAddr() net.Addr { return f.mux.conn.RemoteAddr() }

// SetDeadline is a stub that returns an error
func (f *flowConn) SetDeadline(t time.Time) error {
	return errors.New("setting deadline per flow is not supported")
}

// SetReadDeadline is a stub that returns an error
func (f *flowConn) SetReadDeadline(t time.Time) error {
	return errors.New("setting deadline per flow is not supported")
}

// SetWriteDeadline is a stub that returns an error
func (f *flowConn) SetWriteDeadline(t time.Time) error {
	return errors.New("setting deadline per flow is not supported")
}

// managedFlowConn wraps a flowConn and sends a Close control message when closed
type managedFlowConn struct {
	*flowConn
	writeControl func(muxControlMessage) error
	flowStates   *sync.Map
	closeOnce    sync.Once
}

// Close notifies the peer and tears down the flow.
func (m *managedFlowConn) Close() error {
	m.closeOnce.Do(func() {
		m.flowStates.Delete(m.flowConn.id)
		_ = m.writeControl(muxControlMessage{
			Type:   muxControlTypeClose,
			FlowID: m.flowConn.id,
		})
		_ = m.flowConn.Close()
	})
	return nil
}

// TinyMuxClient represents a client tinymux connection
type TinyMuxClient struct {
	mux       *tinyMuxCore
	control   net.Conn
	controlMu sync.Mutex

	lastPingSent atomic.Int64
	lastPong     atomic.Int64

	pingCtx    context.Context
	pingCancel context.CancelFunc

	openReplyCh chan uint16
	flowStates  sync.Map
}

// NewTinyMuxClient creates a client tinymux connection
func NewTinyMuxClient(ctx context.Context, conn net.Conn) (*TinyMuxClient, error) {
	slog.Debug("tinymux client init started")
	mux := newTinyMuxCore(conn)

	controlFlow := mux.createFlow(0)
	controlKCP, err := transport.WrapKCP(controlFlow)
	if err != nil {
		_ = mux.Close()
		return nil, fmt.Errorf("failed to wrap control channel with kcp: %w", err)
	}

	if _, err := controlKCP.Write([]byte(muxControlMagic)); err != nil {
		_ = controlKCP.Close()
		_ = mux.Close()
		return nil, fmt.Errorf("failed to write control preface: %w", err)
	}

	slog.Debug("tinymux client control preface sent")
	pingCtx, pingCancel := context.WithCancel(ctx)
	client := &TinyMuxClient{
		mux:         mux,
		control:     controlKCP,
		pingCtx:     pingCtx,
		pingCancel:  pingCancel,
		openReplyCh: make(chan uint16, 16),
	}

	now := time.Now().UnixNano()
	client.lastPingSent.Store(now)
	client.lastPong.Store(now)

	go client.pingLoop()
	go client.controlReader()
	return client, nil
}

// pingLoop sends periodic pings and closes tinymux if the server stops responding
func (c *TinyMuxClient) pingLoop() {
	ticker := time.NewTicker(muxClientPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.pingCtx.Done():
			return
		case <-ticker.C:
			sent := c.lastPingSent.Load()
			pong := c.lastPong.Load()
			if pong < sent && time.Since(time.Unix(0, sent)) > muxPingTimeout {
				slog.Warn("tinymux client pong timeout")
				c.pingCancel()
				_ = c.mux.Close()
				return
			}

			c.lastPingSent.Store(time.Now().UnixNano())
			c.controlMu.Lock()
			_ = writeControlMessage(c.control, muxControlMessage{Type: muxControlTypePing})
			c.controlMu.Unlock()
		}
	}
}

// controlReader reads and dispatches incoming control messages from the server
func (c *TinyMuxClient) controlReader() {
	for {
		msg, err := readControlMessage(c.control)
		if err != nil {
			select {
			case <-c.pingCtx.Done():
			default:
				slog.Debug("tinymux client control reader stopped", "error", err)
				c.pingCancel()
				_ = c.mux.Close()
			}
			return
		}
		switch msg.Type {
		case muxControlTypePong:
			c.lastPong.Store(time.Now().UnixNano())
		case muxControlTypeOpen:
			select {
			case c.openReplyCh <- msg.FlowID:
			default:
			}
		case muxControlTypeClose:
			if raw, ok := c.flowStates.LoadAndDelete(msg.FlowID); ok {
				_ = raw.(*managedFlowConn).flowConn.Close()
			}
		case muxControlTypeDisconnect:
			slog.Info("tinymux client received disconnect")
			c.pingCancel()
			_ = c.mux.Close()
			return
		}
	}
}

// Done returns a channel closed when the mux session terminates
func (c *TinyMuxClient) Done() <-chan struct{} { return c.pingCtx.Done() }

// OpenChannel requests a new data flow from the server and returns it
func (c *TinyMuxClient) OpenChannel() (net.Conn, error) {
	if err := c.writeControl(muxControlMessage{Type: muxControlTypeOpen}); err != nil {
		return nil, err
	}
	select {
	case flowID := <-c.openReplyCh:
		fc := c.mux.createFlow(flowID)
		mf := &managedFlowConn{flowConn: fc, writeControl: c.writeControl, flowStates: &c.flowStates}
		c.flowStates.Store(flowID, mf)
		slog.Debug("tinymux channel opened", "side", "client", "flow_id", flowID)
		return mf, nil
	case <-c.pingCtx.Done():
		return nil, errors.New("tinymux client session closed")
	}
}

// Disconnect sends a Disconnect message to the server
func (c *TinyMuxClient) Disconnect() error {
	return c.writeControl(muxControlMessage{Type: muxControlTypeDisconnect})
}

// Close tears down the client mux session
func (c *TinyMuxClient) Close() error {
	if c.pingCancel != nil {
		c.pingCancel()
	}
	return errors.Join(
		func() error {
			if c.control == nil {
				return nil
			}
			return c.control.Close()
		}(),
		func() error {
			if c.mux == nil {
				return nil
			}
			return c.mux.Close()
		}(),
	)
}

// writeControl serializes and writes a control message under the control mutex
func (c *TinyMuxClient) writeControl(msg muxControlMessage) error {
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	return writeControlMessage(c.control, msg)
}

// TinyMuxServer accepts logical channels from one authenticated connection
type TinyMuxServer struct {
	mux       *tinyMuxCore
	control   net.Conn
	controlMu sync.Mutex

	lastPing   atomic.Int64
	flowStates sync.Map
	doneOnce   sync.Once
	done       chan struct{}
}

// NewTinyMuxServer creates a mux server over the provided packet-centric connection
func NewTinyMuxServer(conn net.Conn) (*TinyMuxServer, error) {
	slog.Debug("tinymux server init started")
	mux := newTinyMuxCore(conn)

	controlFlow := mux.createFlow(0)
	controlKCP, err := transport.WrapKCP(controlFlow)
	if err != nil {
		_ = mux.Close()
		return nil, fmt.Errorf("failed to wrap control channel with kcp: %w", err)
	}

	preface := make([]byte, 4)
	if _, err := io.ReadFull(controlKCP, preface); err != nil {
		_ = controlKCP.Close()
		_ = mux.Close()
		return nil, fmt.Errorf("failed to read control preface: %w", err)
	}
	if string(preface) != string(muxControlMagic) {
		_ = controlKCP.Close()
		_ = mux.Close()
		return nil, errors.New("invalid tinymux control preface")
	}
	slog.Debug("tinymux server control preface received")

	return &TinyMuxServer{
		mux:     mux,
		control: controlKCP,
		done:    make(chan struct{}),
	}, nil
}

// AcceptChannels emits fully negotiated data flows
func (s *TinyMuxServer) AcceptChannels(ctx context.Context) <-chan MuxChannel {
	out := make(chan MuxChannel)
	s.lastPing.Store(time.Now().UnixNano())

	go s.pingTimeoutLoop(ctx)
	go func() {
		defer close(out)
		for {
			msg, err := readControlMessage(s.control)
			if err != nil {
				select {
				case <-ctx.Done():
				default:
					slog.Debug("tinymux server control stopped", "error", err)
				}
				s.doneOnce.Do(func() { close(s.done) })
				_ = s.Close()
				return
			}

			switch msg.Type {
			case muxControlTypePing:
				s.lastPing.Store(time.Now().UnixNano())
				s.controlMu.Lock()
				_ = writeControlMessage(s.control, muxControlMessage{Type: muxControlTypePong})
				s.controlMu.Unlock()
			case muxControlTypeOpen:
				fc := s.mux.allocateFlow()
				sf := &managedFlowConn{flowConn: fc, writeControl: s.writeControl, flowStates: &s.flowStates}
				s.flowStates.Store(fc.id, sf)

				s.controlMu.Lock()
				_ = writeControlMessage(s.control, muxControlMessage{
					Type:   muxControlTypeOpen,
					FlowID: fc.id,
				})
				s.controlMu.Unlock()

				slog.Debug("tinymux channel opened", "side", "server", "flow_id", fc.id)
				select {
				case out <- MuxChannel{
					FlowID: fc.id,
					Conn:   sf,
				}:
				case <-ctx.Done():
					_ = s.Close()
					return
				}
			case muxControlTypeClose:
				if raw, ok := s.flowStates.LoadAndDelete(msg.FlowID); ok {
					_ = raw.(*managedFlowConn).flowConn.Close()
				}
			case muxControlTypeDisconnect:
				slog.Info("tinymux server received disconnect")
				s.doneOnce.Do(func() { close(s.done) })
				_ = s.Close()
				return
			}
		}
	}()
	return out
}

// pingTimeoutLoop closes the mux if the client stops sending pings within the timeout window
func (s *TinyMuxServer) pingTimeoutLoop(ctx context.Context) {
	ticker := time.NewTicker(muxPingTimeout)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, s.lastPing.Load())) > muxPingTimeout {
				slog.Warn("tinymux server ping timeout")
				_ = s.Close()
				return
			}
		}
	}
}

// writeControl serializes and writes a control message under the control mutex
func (s *TinyMuxServer) writeControl(msg muxControlMessage) error {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	return writeControlMessage(s.control, msg)
}

// Disconnect sends a Disconnect message to the client
func (s *TinyMuxServer) Disconnect() error {
	return s.writeControl(muxControlMessage{Type: muxControlTypeDisconnect})
}

// Close tears down the server mux session
func (s *TinyMuxServer) Close() error {
	s.doneOnce.Do(func() { close(s.done) })
	return errors.Join(
		func() error {
			if s.control == nil {
				return nil
			}
			return s.control.Close()
		}(),
		func() error {
			if s.mux == nil {
				return nil
			}
			return s.mux.Close()
		}(),
	)
}

// writeControlMessage writes one 4-byte control frame
func writeControlMessage(w io.Writer, msg muxControlMessage) error {
	frame := make([]byte, 4)
	frame[0] = muxControlVersion
	frame[1] = msg.Type
	binary.BigEndian.PutUint16(frame[2:], msg.FlowID)
	_, err := w.Write(frame)
	return err
}

// readControlMessage reads one 4-byte control frame
func readControlMessage(r io.Reader) (muxControlMessage, error) {
	frame := make([]byte, 4)
	if _, err := io.ReadFull(r, frame); err != nil {
		return muxControlMessage{}, err
	}
	if frame[0] != muxControlVersion {
		return muxControlMessage{}, fmt.Errorf("unsupported tinymux control version %d", frame[0])
	}
	msg := muxControlMessage{
		Type:   frame[1],
		FlowID: binary.BigEndian.Uint16(frame[2:]),
	}
	switch msg.Type {
	case muxControlTypeOpen, muxControlTypePing, muxControlTypePong,
		muxControlTypeClose, muxControlTypeDisconnect:
	default:
		return muxControlMessage{}, fmt.Errorf("unknown control message type %d", msg.Type)
	}
	return msg, nil
}

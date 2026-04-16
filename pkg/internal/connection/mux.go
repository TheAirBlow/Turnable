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

	"github.com/xtaci/smux"

	"github.com/theairblow/turnable/pkg/common"
)

const (
	vpnMuxControlVersion          byte = 3
	vpnMuxControlTypeOpen         byte = 1
	vpnMuxControlTypePing         byte = 2
	vpnMuxControlTypePong         byte = 3
	vpnMuxControlTypeCloseRequest byte = 4
	vpnMuxControlTypeCloseAck     byte = 5
	vpnMuxControlTypeForceClose   byte = 6
	vpnMuxControlTypeDisconnect   byte = 7
)

const (
	vpnMuxClientPingInterval = 1 * time.Second // how often client sends PING
	vpnMuxPingTimeout        = 5 * time.Second // both sides timeout if no reply
)

var vpnMuxControlMagic = []byte{'M', 'X', 'C', '1'}

// smux frame size - matches the default, set explicitly for clarity.
// Do NOT lower this; small frames cause excessive fragmentation and latency on TLS handshakes.
const vpnMuxMaxFrameSize = 32768

// VPNMuxControlMessage is sent on the dedicated control stream to open/close data channels.
type VPNMuxControlMessage struct {
	Type     byte
	StreamID uint32
}

// VPNMuxChannel is one negotiated logical data channel.
type VPNMuxChannel struct {
	ID             uint32
	Stream         io.ReadWriteCloser
	CloseRequested <-chan struct{} // closed when remote sends CloseRequest
}

// vpnMuxDataStream is a raw smux stream wrapper holding its stream ID.
type vpnMuxDataStream struct {
	id     uint32
	stream *smux.Stream
}

// vpnMuxManagedStream is the client-side channel stream.
// Read is served from a pipe fed by a background goroutine, which decouples
// smux stream lifetime from half-close signaling.
type vpnMuxManagedStream struct {
	stream    *smux.Stream
	id        uint32
	pipeR     *io.PipeReader
	pipeW     *io.PipeWriter
	writeCtrl func(VPNMuxControlMessage) error
	onClose   func() // cleanup: remove from managedStreams

	writeClosed      atomic.Bool
	closeReqReceived atomic.Bool // remote sent CloseRequest (remote done writing)
	closeAckReceived atomic.Bool // remote sent CloseAck (remote done writing, ack of our CloseRequest)
	closeOnce        sync.Once
}

// newManagedStream creates a new client-side managed stream with a background read loop.
func newManagedStream(
	stream *smux.Stream,
	writeCtrl func(VPNMuxControlMessage) error,
	onClose func(),
) *vpnMuxManagedStream {
	pipeR, pipeW := io.Pipe()
	m := &vpnMuxManagedStream{
		stream:    stream,
		id:        stream.ID(),
		pipeR:     pipeR,
		pipeW:     pipeW,
		writeCtrl: writeCtrl,
		onClose:   onClose,
	}
	go m.readLoop()
	return m
}

// readLoop copies from smux stream into the pipe, draining the smux buffer
// before signaling EOF when a CloseRequest deadline interrupt fires.
func (m *vpnMuxManagedStream) readLoop() {
	defer m.pipeW.Close()
	buf := make([]byte, vpnMuxMaxFrameSize)
	for {
		n, err := m.stream.Read(buf)
		if n > 0 {
			if _, werr := m.pipeW.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if isNetTimeout(err) && m.closeReqReceived.Load() {
				return // clean close: remote done writing, smux buffer fully drained
			}
			if !isEOFOrClosed(err) {
				_ = m.pipeW.CloseWithError(err)
			}
			return
		}
	}
}

// Read reads from the managed stream pipe.
func (m *vpnMuxManagedStream) Read(p []byte) (int, error) { return m.pipeR.Read(p) }

// Write sends data on the managed stream.
func (m *vpnMuxManagedStream) Write(p []byte) (int, error) {
	if m.writeClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	return m.stream.Write(p)
}

// CloseWrite performs a graceful half-close.
// If the remote already sent CloseRequest: sends CloseAck and closes smux stream
// (which causes the remote's readLoop to get EOF → their pipeR returns EOF → their b→a goroutine exits).
// Otherwise: initiates close by sending CloseRequest.
func (m *vpnMuxManagedStream) CloseWrite() error {
	if m.writeClosed.Swap(true) {
		return nil
	}
	if m.closeReqReceived.Load() {
		err := m.writeCtrl(VPNMuxControlMessage{Type: vpnMuxControlTypeCloseAck, StreamID: m.id})
		_ = m.stream.Close()
		return err
	}
	return m.writeCtrl(VPNMuxControlMessage{Type: vpnMuxControlTypeCloseRequest, StreamID: m.id})
}

// signalCloseRequest is called when the remote sends CloseRequest.
// Sets the deadline on the smux stream to wake up readLoop; readLoop will drain
// any buffered data then close pipeW, delivering EOF to the b→a goroutine.
func (m *vpnMuxManagedStream) signalCloseRequest() {
	m.closeReqReceived.Store(true)
	_ = m.stream.SetReadDeadline(time.Now())
}

// signalCloseAck is called when the remote sends CloseAck (acking our CloseRequest).
// The remote calls stream.Close() after sending CloseAck, so our readLoop will
// get EOF from smux FIN naturally - no explicit action needed here.
func (m *vpnMuxManagedStream) signalCloseAck() {
	m.closeAckReceived.Store(true)
}

// signalRST forces an immediate close of the managed stream.
func (m *vpnMuxManagedStream) signalRST() {
	_ = m.pipeW.CloseWithError(io.ErrUnexpectedEOF)
	_ = m.stream.Close()
}

// Close performs a full close of the managed stream.
func (m *vpnMuxManagedStream) Close() error {
	var err error
	m.closeOnce.Do(func() {
		if m.onClose != nil {
			m.onClose()
		}
		// If no clean close was initiated, send RST so the remote knows immediately.
		if !m.writeClosed.Load() {
			_ = m.writeCtrl(VPNMuxControlMessage{Type: vpnMuxControlTypeForceClose, StreamID: m.id})
		}
		_ = m.pipeR.Close()
		err = m.stream.Close()
	})
	slog.Debug("vpnmux channel closed", "side", "client", "stream_id", m.id)
	return err
}

// ------ vpnMuxServerStream (server side) ------

// vpnMuxServerStream mirrors vpnMuxManagedStream for the server side.
type vpnMuxServerStream struct {
	stream    *smux.Stream
	id        uint32
	pipeR     *io.PipeReader
	pipeW     *io.PipeWriter
	writeCtrl func(VPNMuxControlMessage) error
	onClose   func() // cleanup: remove from activeStreams

	closeReqCh   chan struct{} // closed when client sends CloseRequest
	closeReqOnce sync.Once

	writeClosed      atomic.Bool
	closeReqReceived atomic.Bool
	closeOnce        sync.Once
}

// newServerStream creates a new server-side stream with a background read loop.
func newServerStream(
	stream *smux.Stream,
	writeCtrl func(VPNMuxControlMessage) error,
	onClose func(),
) *vpnMuxServerStream {
	pipeR, pipeW := io.Pipe()
	s := &vpnMuxServerStream{
		stream:     stream,
		id:         stream.ID(),
		pipeR:      pipeR,
		pipeW:      pipeW,
		writeCtrl:  writeCtrl,
		onClose:    onClose,
		closeReqCh: make(chan struct{}),
	}
	go s.readLoop()
	return s
}

// readLoop copies data from the smux stream into the pipe until EOF or error.
func (s *vpnMuxServerStream) readLoop() {
	defer s.pipeW.Close()
	buf := make([]byte, vpnMuxMaxFrameSize)
	for {
		n, err := s.stream.Read(buf)
		if n > 0 {
			if _, werr := s.pipeW.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if isNetTimeout(err) && s.closeReqReceived.Load() {
				return
			}
			if !isEOFOrClosed(err) {
				_ = s.pipeW.CloseWithError(err)
			}
			return
		}
	}
}

// Read reads from the server stream pipe.
func (s *vpnMuxServerStream) Read(p []byte) (int, error) { return s.pipeR.Read(p) }

// Write sends data on the server stream.
func (s *vpnMuxServerStream) Write(p []byte) (int, error) {
	if s.writeClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	return s.stream.Write(p)
}

// CloseWrite performs a graceful half-close on the server stream.
func (s *vpnMuxServerStream) CloseWrite() error {
	if s.writeClosed.Swap(true) {
		return nil
	}
	if s.closeReqReceived.Load() {
		err := s.writeCtrl(VPNMuxControlMessage{Type: vpnMuxControlTypeCloseAck, StreamID: s.id})
		_ = s.stream.Close()
		return err
	}
	return s.writeCtrl(VPNMuxControlMessage{Type: vpnMuxControlTypeCloseRequest, StreamID: s.id})
}

// signalCloseRequest marks the stream as receiving a CloseRequest from the client.
func (s *vpnMuxServerStream) signalCloseRequest() {
	s.closeReqOnce.Do(func() {
		s.closeReqReceived.Store(true)
		close(s.closeReqCh)
		_ = s.stream.SetReadDeadline(time.Now())
	})
}

// signalRST forces an immediate close of the server stream.
func (s *vpnMuxServerStream) signalRST() {
	_ = s.pipeW.CloseWithError(io.ErrUnexpectedEOF)
	_ = s.stream.Close()
}

// Close performs a full close of the server stream, sending RST if needed.
func (s *vpnMuxServerStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.onClose != nil {
			s.onClose()
		}
		if !s.writeClosed.Load() {
			_ = s.writeCtrl(VPNMuxControlMessage{Type: vpnMuxControlTypeForceClose, StreamID: s.id})
		}
		_ = s.pipeR.Close()
		err = s.stream.Close()
	})
	slog.Debug("vpnmux channel closed", "side", "server", "stream_id", s.id)
	return err
}

// VPNMuxClient wraps one authenticated relay stream and opens logical channels on demand.
type VPNMuxClient struct {
	session        *smux.Session
	control        io.ReadWriteCloser
	controlMu      sync.Mutex
	lastPing       atomic.Int64 // last PING received from server
	lastPong       atomic.Int64 // last PONG received from server
	pingCtx        context.Context
	pingCancel     context.CancelFunc
	managedStreams sync.Map // uint32 → *vpnMuxManagedStream
}

// NewVPNMuxClient creates a mux client over the provided transport.
// The transport must already be authenticated and encrypted at a lower layer.
func NewVPNMuxClient(transport io.ReadWriteCloser) (*VPNMuxClient, error) {
	slog.Debug("vpnmux client init started")
	session, err := smux.Client(transport, newVPNMuxSMUXConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create vpnmux client session: %w", err)
	}

	controlStream, err := session.OpenStream()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("failed to open vpnmux control stream: %w", err)
	}

	if err := common.WriteFullRetry(controlStream, vpnMuxControlMagic); err != nil {
		_ = controlStream.Close()
		_ = session.Close()
		return nil, fmt.Errorf("failed to write vpnmux control preface: %w", err)
	}
	slog.Debug("vpnmux client control preface sent")

	pingCtx, pingCancel := context.WithCancel(context.Background())
	client := &VPNMuxClient{
		session:    session,
		control:    controlStream,
		pingCtx:    pingCtx,
		pingCancel: pingCancel,
	}
	now := time.Now().UnixNano()
	client.lastPing.Store(now)
	client.lastPong.Store(now)

	// Client ping sender: sends PINGs to server and checks for PONG timeout.
	go func() {
		ticker := time.NewTicker(vpnMuxClientPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-pingCtx.Done():
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, client.lastPong.Load())) > vpnMuxPingTimeout {
					slog.Warn("vpnmux client pong timeout, closing session")
					pingCancel()
					_ = session.Close()
					return
				}
				client.controlMu.Lock()
				_ = VPNMuxWriteControlMessage(controlStream, VPNMuxControlMessage{Type: vpnMuxControlTypePing})
				client.controlMu.Unlock()
			}
		}
	}()

	// Client control reader: handles incoming messages from server.
	go func() {
		for {
			msg, err := VPNMuxReadControlMessage(controlStream)
			if err != nil {
				select {
				case <-pingCtx.Done():
				default:
					slog.Debug("vpnmux client control reader stopped", "error", err)
					pingCancel()
					_ = session.Close()
				}
				return
			}
			switch msg.Type {
			case vpnMuxControlTypePing:
				client.lastPing.Store(time.Now().UnixNano())
				client.controlMu.Lock()
				_ = VPNMuxWriteControlMessage(controlStream, VPNMuxControlMessage{Type: vpnMuxControlTypePong})
				client.controlMu.Unlock()
			case vpnMuxControlTypePong:
				client.lastPong.Store(time.Now().UnixNano())
			case vpnMuxControlTypeCloseRequest:
				if raw, ok := client.managedStreams.Load(msg.StreamID); ok {
					raw.(*vpnMuxManagedStream).signalCloseRequest()
				}
			case vpnMuxControlTypeCloseAck:
				if raw, ok := client.managedStreams.Load(msg.StreamID); ok {
					raw.(*vpnMuxManagedStream).signalCloseAck()
				}
			case vpnMuxControlTypeForceClose:
				if raw, ok := client.managedStreams.Load(msg.StreamID); ok {
					raw.(*vpnMuxManagedStream).signalRST()
				}
			case vpnMuxControlTypeDisconnect:
				slog.Info("vpnmux client received disconnect from server, closing session")
				pingCancel()
				_ = session.Close()
				return
			}
		}
	}()

	return client, nil
}

// Done returns a channel that is closed when the mux client session terminates
// (ping timeout, connection error, or a Disconnect message from the server).
// Callers can use this to detect session death and trigger a full reconnect.
func (c *VPNMuxClient) Done() <-chan struct{} {
	return c.pingCtx.Done()
}

// OpenChannel allocates one data channel and announces it through control.
func (c *VPNMuxClient) OpenChannel() (io.ReadWriteCloser, error) {
	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open vpnmux data stream: %w", err)
	}
	id := stream.ID()
	slog.Debug("vpnmux client stream allocated", "stream_id", id)

	if err := c.writeControl(VPNMuxControlOpen(id)); err != nil {
		_ = stream.Close()
		return nil, err
	}
	slog.Debug("vpnmux channel opened", "side", "client", "stream_id", id)

	ms := newManagedStream(stream, c.writeControl, func() {
		c.managedStreams.Delete(id)
	})
	c.managedStreams.Store(id, ms)
	return ms, nil
}

// SendDisconnect sends a Disconnect control message to the server, notifying it that the
// client is disconnecting and the server should tear down the session immediately.
// Best-effort: errors are ignored by the caller.
func (c *VPNMuxClient) SendDisconnect() error {
	return c.writeControl(VPNMuxControlMessage{Type: vpnMuxControlTypeDisconnect})
}

// Close tears down the client mux session.
func (c *VPNMuxClient) Close() error {
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
			if c.session == nil {
				return nil
			}
			return c.session.Close()
		}(),
	)
}

func (c *VPNMuxClient) writeControl(msg VPNMuxControlMessage) error {
	c.controlMu.Lock()
	defer c.controlMu.Unlock()
	slog.Debug("vpnmux control write", "side", "client", "type", msg.Type, "stream_id", msg.StreamID)
	if err := VPNMuxWriteControlMessage(c.control, msg); err != nil {
		return fmt.Errorf("failed to write vpnmux control frame: %w", err)
	}
	return nil
}

// VPNMuxServer accepts logical channels from one authenticated relay stream.
type VPNMuxServer struct {
	session       *smux.Session
	control       io.ReadWriteCloser
	controlMu     sync.Mutex
	lastPing      atomic.Int64 // last PING received from client
	activeStreams sync.Map     // uint32 → *vpnMuxServerStream
	sessionUUID   string
	doneOnce      sync.Once
	done          chan struct{} // closed when control loop exits for any reason
}

// SetSessionUUID sets the session UUID used in log messages.
func (s *VPNMuxServer) SetSessionUUID(id string) { s.sessionUUID = id }

// NewVPNMuxServer creates a mux server over the provided transport.
// The transport must already be authenticated and encrypted at a lower layer.
func NewVPNMuxServer(transport io.ReadWriteCloser) (*VPNMuxServer, error) {
	slog.Debug("vpnmux server init started")
	session, err := smux.Server(transport, newVPNMuxSMUXConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create vpnmux server session: %w", err)
	}

	controlStream, err := session.AcceptStream()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("failed to accept vpnmux control stream: %w", err)
	}

	preface := make([]byte, len(vpnMuxControlMagic))
	if _, err := common.ReadFullRetry(controlStream, preface); err != nil {
		_ = controlStream.Close()
		_ = session.Close()
		return nil, fmt.Errorf("failed to read vpnmux control preface: %w", err)
	}
	slog.Debug("vpnmux server control preface received")
	if string(preface) != string(vpnMuxControlMagic) {
		_ = controlStream.Close()
		_ = session.Close()
		return nil, errors.New("invalid vpnmux control preface")
	}

	return &VPNMuxServer{
		session: session,
		control: controlStream,
		done:    make(chan struct{}),
	}, nil
}

// AcceptChannels emits fully negotiated channels (control OPEN + data stream).
func (s *VPNMuxServer) AcceptChannels(ctx context.Context) <-chan VPNMuxChannel {
	out := make(chan VPNMuxChannel)

	controlCh := make(chan VPNMuxControlMessage)
	controlErrCh := make(chan error, 1)
	dataCh := make(chan vpnMuxDataStream)
	dataErrCh := make(chan error, 1)

	// Initialize timestamp so first check doesn't immediately time out.
	s.lastPing.Store(time.Now().UnixNano())

	go s.controlLoop(controlCh, controlErrCh)
	go s.dataLoop(dataCh, dataErrCh)

	// Timeout goroutine: closes session if client stops sending PINGs.
	go func() {
		ticker := time.NewTicker(vpnMuxPingTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.done:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, s.lastPing.Load())) > vpnMuxPingTimeout {
					slog.Warn("vpnmux server client ping timeout, closing session", "session_uuid", s.sessionUUID)
					_ = s.Close()
					return
				}
			}
		}
	}()

	go func() {
		defer close(out)

		openByID := make(map[uint32]VPNMuxControlMessage)
		streamByID := make(map[uint32]*smux.Stream)

		emitChannel := func(id uint32, raw *smux.Stream) bool {
			ss := newServerStream(raw, s.writeControl, func() {
				s.activeStreams.Delete(id)
			})
			s.activeStreams.Store(id, ss)
			slog.Debug("vpnmux channel opened", "side", "server", "stream_id", id, "session_uuid", s.sessionUUID)
			select {
			case out <- VPNMuxChannel{ID: id, Stream: ss, CloseRequested: ss.closeReqCh}:
				return true
			case <-ctx.Done():
				s.activeStreams.Delete(id)
				_ = ss.Close()
				_ = s.Close()
				return false
			}
		}

		for {
			select {
			case <-ctx.Done():
				_ = s.Close()
				return
			case msg, ok := <-controlCh:
				if !ok {
					controlCh = nil
					continue
				}
				switch msg.Type {
				case vpnMuxControlTypeOpen:
					if stream, ok := streamByID[msg.StreamID]; ok {
						delete(streamByID, msg.StreamID)
						if !emitChannel(msg.StreamID, stream) {
							return
						}
						continue
					}
					openByID[msg.StreamID] = msg
				case vpnMuxControlTypeCloseRequest:
					// Route to active stream if already emitted.
					if raw, ok := s.activeStreams.Load(msg.StreamID); ok {
						raw.(*vpnMuxServerStream).signalCloseRequest()
					}
					// Clean up pending (never-emitted) state.
					if stream, ok := streamByID[msg.StreamID]; ok {
						delete(streamByID, msg.StreamID)
						_ = stream.Close()
					}
					delete(openByID, msg.StreamID)
				case vpnMuxControlTypeCloseAck:
					// Client acknowledged our CloseRequest; it will call stream.Close().
					// readLoop on server side will get EOF naturally - nothing to do.
				case vpnMuxControlTypeForceClose:
					if raw, ok := s.activeStreams.Load(msg.StreamID); ok {
						raw.(*vpnMuxServerStream).signalRST()
					}
					if stream, ok := streamByID[msg.StreamID]; ok {
						delete(streamByID, msg.StreamID)
						_ = stream.Close()
					}
					delete(openByID, msg.StreamID)
				}
			case ds, ok := <-dataCh:
				if !ok {
					dataCh = nil
					continue
				}
				if _, ok := openByID[ds.id]; ok {
					delete(openByID, ds.id)
					if !emitChannel(ds.id, ds.stream) {
						return
					}
					continue
				}
				streamByID[ds.id] = ds.stream
			case err := <-controlErrCh:
				if err != nil && !errors.Is(err, io.EOF) {
					_ = s.Close()
				}
				return
			case err := <-dataErrCh:
				if err != nil && !errors.Is(err, io.EOF) {
					_ = s.Close()
				}
				return
			}
		}
	}()

	return out
}

func (s *VPNMuxServer) controlLoop(out chan<- VPNMuxControlMessage, errCh chan<- error) {
	defer close(out)
	defer s.doneOnce.Do(func() { close(s.done) })
	for {
		msg, err := VPNMuxReadControlMessage(s.control)
		if err != nil {
			slog.Debug("vpnmux control loop stopped", "side", "server", "error", err, "session_uuid", s.sessionUUID)
			errCh <- err
			return
		}
		slog.Debug("vpnmux control read", "side", "server", "type", msg.Type, "stream_id", msg.StreamID, "session_uuid", s.sessionUUID)
		switch msg.Type {
		case vpnMuxControlTypePing:
			s.lastPing.Store(time.Now().UnixNano())
			s.controlMu.Lock()
			_ = VPNMuxWriteControlMessage(s.control, VPNMuxControlMessage{Type: vpnMuxControlTypePong})
			s.controlMu.Unlock()
			continue
		case vpnMuxControlTypeDisconnect:
			slog.Info("vpnmux server received disconnect from client, closing session", "session_uuid", s.sessionUUID)
			_ = s.Close()
			errCh <- io.EOF
			return
		}
		out <- msg
	}
}

func (s *VPNMuxServer) dataLoop(out chan<- vpnMuxDataStream, errCh chan<- error) {
	defer close(out)
	for {
		stream, err := s.session.AcceptStream()
		if err != nil {
			slog.Debug("vpnmux data loop stopped", "side", "server", "error", err, "session_uuid", s.sessionUUID)
			errCh <- err
			return
		}
		slog.Debug("vpnmux data stream accepted", "side", "server", "stream_id", stream.ID(), "session_uuid", s.sessionUUID)
		out <- vpnMuxDataStream{id: stream.ID(), stream: stream}
	}
}

// SendDisconnect sends a Disconnect control message to the client, notifying it that the
// server is shutting down and the client should reconnect from scratch.
// Best-effort: errors are ignored by the caller.
func (s *VPNMuxServer) SendDisconnect() error {
	return s.writeControl(VPNMuxControlMessage{Type: vpnMuxControlTypeDisconnect})
}

// Close tears down the server mux session.
func (s *VPNMuxServer) Close() error {
	return errors.Join(
		func() error {
			if s.control == nil {
				return nil
			}
			return s.control.Close()
		}(),
		func() error {
			if s.session == nil {
				return nil
			}
			return s.session.Close()
		}(),
	)
}

func (s *VPNMuxServer) writeControl(msg VPNMuxControlMessage) error {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	slog.Debug("vpnmux control write", "side", "server", "type", msg.Type, "stream_id", msg.StreamID)
	if err := VPNMuxWriteControlMessage(s.control, msg); err != nil {
		return fmt.Errorf("failed to write vpnmux control frame: %w", err)
	}
	return nil
}

// VPNMuxWriteControlMessage writes one control frame to the control stream.
func VPNMuxWriteControlMessage(w io.Writer, msg VPNMuxControlMessage) error {
	frame := make([]byte, 6)
	frame[0] = vpnMuxControlVersion
	frame[1] = msg.Type
	binary.BigEndian.PutUint32(frame[2:], msg.StreamID)
	return common.WriteFullRetry(w, frame)
}

// VPNMuxReadControlMessage reads one control frame from the control stream.
func VPNMuxReadControlMessage(r io.Reader) (VPNMuxControlMessage, error) {
	frame := make([]byte, 6)
	if _, err := common.ReadFullRetry(r, frame); err != nil {
		return VPNMuxControlMessage{}, err
	}
	if frame[0] != vpnMuxControlVersion {
		return VPNMuxControlMessage{}, fmt.Errorf("unsupported vpnmux control version %d", frame[0])
	}

	msg := VPNMuxControlMessage{
		Type:     frame[1],
		StreamID: binary.BigEndian.Uint32(frame[2:6]),
	}
	switch msg.Type {
	case vpnMuxControlTypeOpen, vpnMuxControlTypeCloseRequest, vpnMuxControlTypePing, vpnMuxControlTypePong,
		vpnMuxControlTypeCloseAck, vpnMuxControlTypeForceClose, vpnMuxControlTypeDisconnect:
		// valid
	default:
		return VPNMuxControlMessage{}, fmt.Errorf("unknown vpnmux control message type %d", msg.Type)
	}
	return msg, nil
}

// VPNMuxControlOpen creates an OPEN control message.
func VPNMuxControlOpen(streamID uint32) VPNMuxControlMessage {
	return VPNMuxControlMessage{Type: vpnMuxControlTypeOpen, StreamID: streamID}
}

// VPNMuxControlCloseRequest creates a CloseRequest control message.
func VPNMuxControlCloseRequest(streamID uint32) VPNMuxControlMessage {
	return VPNMuxControlMessage{Type: vpnMuxControlTypeCloseRequest, StreamID: streamID}
}

// VPNMuxWritePacket writes one length-prefixed UDP packet into a channel stream.
func VPNMuxWritePacket(w io.Writer, payload []byte) error {
	if len(payload) > 0xFFFF {
		return fmt.Errorf("packet too large: %d bytes", len(payload))
	}
	slog.Debug("vpnmux udp packet write", "bytes", len(payload))
	header := []byte{0, 0}
	binary.BigEndian.PutUint16(header, uint16(len(payload)))
	if err := common.WriteFullRetry(w, header); err != nil {
		return err
	}
	return common.WriteFullRetry(w, payload)
}

// VPNMuxReadPacket reads one length-prefixed UDP packet from a channel stream.
func VPNMuxReadPacket(r io.Reader, maxSize int) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := common.ReadFullRetry(r, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header))
	if maxSize > 0 && size > maxSize {
		return nil, fmt.Errorf("packet too large: %d (max %d)", size, maxSize)
	}
	slog.Debug("vpnmux udp packet read", "bytes", size)

	payload := make([]byte, size)
	if size == 0 {
		return payload, nil
	}
	if _, err := common.ReadFullRetry(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func newVPNMuxSMUXConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.MaxFrameSize = vpnMuxMaxFrameSize
	cfg.MaxStreamBuffer = 1 * 1024 * 1024 // 1 MB per stream - reduces flow-control stalls under load
	return cfg
}

// framedUDPStream wraps a byte-stream ReadWriteCloser with length-prefix packet framing.
// Used to carry UDP datagrams over vpnmux byte-stream channels while preserving packet boundaries.
// Write prepends a 2-byte big-endian length header; Read strips it and returns one full payload.
type framedUDPStream struct {
	inner io.ReadWriteCloser
}

func newFramedUDPStream(inner io.ReadWriteCloser) io.ReadWriteCloser {
	return &framedUDPStream{inner: inner}
}

func (f *framedUDPStream) Read(p []byte) (int, error) {
	packet, err := VPNMuxReadPacket(f.inner, len(p))
	if err != nil {
		return 0, err
	}
	return copy(p, packet), nil
}

func (f *framedUDPStream) Write(p []byte) (int, error) {
	if err := VPNMuxWritePacket(f.inner, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *framedUDPStream) Close() error {
	return f.inner.Close()
}

// isNetTimeout reports whether err is a network timeout error.
func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isEOFOrClosed reports whether err represents a normal end-of-stream.
func isEOFOrClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
		isConnectionClosed(err)
}

// isConnectionClosed reports whether err is a "use of closed network connection" error.
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return len(s) > 0 && (containsStr(s, "use of closed network connection") || containsStr(s, "already closed"))
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findStr(s, sub))
}

func findStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

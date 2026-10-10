package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/connection"
	"github.com/theairblow/turnable/pkg/mpath"
	"github.com/theairblow/turnable/pkg/platform"
	"github.com/theairblow/turnable/pkg/protocol"
	"github.com/theairblow/turnable/pkg/transport"
)

const (
	relayHandshakeVersion byte = 3 // relay handshake and auth message version

	relayHelloTypePrimary   byte = 1 // legacy hello opening a session
	relayHelloTypeSecondary byte = 2 // legacy hello joining a session

	relayAckOK  byte = 0 // ack: accepted
	relayAckErr byte = 1 // ack: rejected with a message

	relayHandshakeTimeout = 10 * time.Second // limit for each handshake step
)

// ErrAckRejected is returned when the server sends an error ACK during handshake
type ErrAckRejected struct {
	msg string // rejection message from the server
}

// Error returns the server's rejection message
func (e *ErrAckRejected) Error() string { return e.msg }

// Handler represent a relay connection handler
type Handler struct {
	running atomic.Bool // the handler is started or connected

	// server-side
	serverConfig *ServerConfig
	provider     providers.Provider // user and route source
	proto        protocol.Handler   // protocol listener
	sessions     sync.Map           // legacy sessions by UUID

	mpathServer   *mpath.Server // accepts mpath sessions
	mpathSessions sync.Map      // live mpath session muxes

	// client-side
	platform  platform.Handler
	muxClient *connection.TinyMuxClient // legacy mux client
	peerConn  *connection.PeerConn      // legacy peer aggregator
	mpath     *mpathClientState         // live mpath session
	cancel    context.CancelFunc        // cancels the current session

	clientConfig    *ClientConfig           // config being connected with
	sessionUUID     string                  // current session UUID
	reconnecting    atomic.Bool             // a full reconnect is running
	reconnectMu     sync.Mutex              // serializes session setup
	stateMu         sync.RWMutex            // guards the client state
	reconnectCtx    context.Context         // lifetime context for reconnects
	reconnectCancel context.CancelFunc      // cancels reconnectCtx
	events          *connection.EventStream // connectivity events for the caller

	log *slog.Logger // logger
}

// SetLogger changes the slog logger instance
func (D *Handler) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	D.log = log
}

// relayServerSession tracks a multi-peer server-side session
type relayServerSession struct {
	peerConn  *connection.PeerConn                     // peer aggregator
	muxServer atomic.Pointer[connection.TinyMuxServer] // mux server once set up
	userUUID  string                                   // authenticated user
	routes    []providers.Route                        // routes authorized for the session
	fullEnc   bool                                     // peers carry encrypted conns
}

// ID returns the unique ID of this handler
func (D *Handler) ID() string {
	return "relay"
}

// Start starts the server listener
func (D *Handler) Start(rawConfig config.Config, provider providers.Provider) error {
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

	cfg, ok := rawConfig.(*ServerConfig)
	if !ok {
		return errors.New("invalid config instance")
	}

	handler, err := protocol.GetHandler(cfg.Proto)
	if err != nil {
		return err
	}

	key, err := mpath.ParseServerKey(cfg.PrivKey)
	if err != nil {
		return err
	}

	if err := handler.Start(cfg.ListenAddr); err != nil {
		return err
	}

	D.mpathServer = mpath.NewServer(key, mpathConfig(D.log))

	D.serverConfig = cfg
	D.provider = provider
	D.proto = handler
	success = true
	return nil
}

// Stop stops the relay-side protocol listener
func (D *Handler) Stop() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	protoHandler := D.proto
	D.serverConfig = nil
	D.proto = nil

	if protoHandler == nil {
		return nil
	}

	D.sessions.Range(func(_, val any) bool {
		sess := val.(*relayServerSession)
		if ms := sess.muxServer.Load(); ms != nil {
			_ = ms.Disconnect()
		}
		return true
	})
	D.mpathSessions.Range(func(key, _ any) bool {
		_ = key.(*mpath.Mux).Close()
		return true
	})

	time.Sleep(100 * time.Millisecond)

	return protoHandler.Stop()
}

// Connect connects to a remote server, returning a channel of connectivity transitions
func (D *Handler) Connect(rawConfig config.Config) (<-chan connection.ConnectEvent, error) {
	if !D.running.CompareAndSwap(false, true) {
		return nil, errors.New("already running")
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

	cfg, ok := rawConfig.(*ClientConfig)
	if !ok {
		return nil, errors.New("invalid config instance")
	}

	if cfg.Proto == "none" {
		D.log.Warn("using no protocol is dangerous, please reconsider!")
	}

	if cfg.Routes[0].Transport != "mpath" {
		D.log.Warn("routes use legacy transports, which are slower and less reliable. leave transport empty to use mpath or specify it explicitly.")
	}

	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())
	events := connection.NewEventStream()
	D.stateMu.Lock()
	D.clientConfig = cfg
	D.reconnectCtx = reconnectCtx
	D.reconnectCancel = reconnectCancel
	D.events = events
	D.stateMu.Unlock()

	connection.RunReconnectLoop(reconnectCtx, D.log, &D.reconnecting, events, "initial connect", D.connectClientSession)

	success = true
	return events.Chan(), nil
}

// OpenChannel opens a new logical data channel
func (D *Handler) OpenChannel(routeIdx byte) (net.Conn, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}
	if D.reconnecting.Load() {
		return nil, connection.ErrReconnecting
	}

	D.stateMu.RLock()
	muxClient := D.muxClient
	mp := D.mpath
	cfg := D.clientConfig
	D.stateMu.RUnlock()

	if mp != nil {
		return mp.openChannel(routeIdx)
	}

	if muxClient == nil {
		return nil, errors.New("relay: no active mux connection")
	}

	stream, err := muxClient.OpenChannel(routeIdx)
	if err != nil {
		D.stateMu.Lock()
		if D.muxClient == muxClient {
			D.muxClient = nil
		}
		D.stateMu.Unlock()

		_ = muxClient.Close()
		return nil, fmt.Errorf("relay: mux channel open failed: %w", err)
	}

	if cfg == nil {
		_ = stream.Close()
		return nil, errors.New("relay: no client config")
	}

	transportID := "none"
	if int(routeIdx) < len(cfg.Routes) {
		if t := cfg.Routes[routeIdx].Transport; t != "" {
			transportID = t
		}
	}

	handler, err := transport.GetHandler(transportID)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("relay: transport setup: %w", err)
	}

	wrapped, err := handler.WrapClient(stream)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("relay: transport wrap: %w", err)
	}

	return wrapped, nil
}

// Disconnect gracefully disconnects from the current remote server
func (D *Handler) Disconnect() error {
	if !D.running.CompareAndSwap(true, false) {
		return nil
	}

	D.stateMu.Lock()
	cancel := D.cancel
	platformHandler := D.platform
	muxClient := D.muxClient
	peerConn := D.peerConn
	reconnectCancel := D.reconnectCancel
	events := D.events
	mp := D.mpath
	D.mpath = nil
	D.cancel = nil
	D.platform = nil
	D.muxClient = nil
	D.peerConn = nil
	D.reconnectCtx = nil
	D.reconnectCancel = nil
	D.clientConfig = nil
	D.sessionUUID = ""
	D.events = nil
	D.stateMu.Unlock()

	if cancel != nil {
		cancel()
	}

	if reconnectCancel != nil {
		reconnectCancel()
	}

	if events != nil {
		events.Close()
	}

	if mp != nil {
		_ = mp.mux.Close()
	}

	return errors.Join(
		func() error {
			if muxClient == nil {
				return nil
			}
			_ = muxClient.Disconnect()
			return muxClient.Close()
		}(),
		func() error {
			if peerConn == nil {
				return nil
			}
			return peerConn.Close()
		}(),
		func() error {
			if platformHandler == nil {
				return nil
			}
			return platformHandler.Disconnect()
		}(),
	)
}

// Close forcibly closes the current remove server connection
func (D *Handler) Close() error {
	if !D.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	D.stateMu.Lock()
	cancel := D.cancel
	platformHandler := D.platform
	muxClient := D.muxClient
	peerConn := D.peerConn
	reconnectCancel := D.reconnectCancel
	events := D.events
	mp := D.mpath
	D.mpath = nil
	D.cancel = nil
	D.platform = nil
	D.muxClient = nil
	D.peerConn = nil
	D.reconnectCtx = nil
	D.reconnectCancel = nil
	D.clientConfig = nil
	D.sessionUUID = ""
	D.events = nil
	D.stateMu.Unlock()

	if cancel != nil {
		cancel()
	}

	if reconnectCancel != nil {
		reconnectCancel()
	}

	if events != nil {
		events.Close()
	}

	if mp != nil {
		_ = mp.mux.Close()
	}

	return errors.Join(
		func() error {
			if muxClient == nil {
				return nil
			}
			return muxClient.Close()
		}(),
		func() error {
			if peerConn == nil {
				return nil
			}
			return peerConn.Close()
		}(),
		func() error {
			if platformHandler == nil {
				return nil
			}
			return platformHandler.Close()
		}(),
	)
}

// AcceptClients accepts and emits new authenticated server clients
func (D *Handler) AcceptClients(ctx context.Context) (<-chan connection.ServerClient, error) {
	if !D.running.Load() {
		return nil, errors.New("not running")
	}

	out := make(chan connection.ServerClient)
	protoHandler := D.proto
	serverCfg := D.serverConfig

	// out closes only after every producer has stopped
	var producers sync.WaitGroup
	acceptCtx, stopAccept := context.WithCancel(ctx)
	producers.Add(2)
	go func() {
		producers.Wait()
		close(out)
	}()
	go func() {
		defer producers.Done()
		D.serveMpathSessions(acceptCtx, out)
	}()

	go func() {
		defer producers.Done()
		defer stopAccept()

		if protoHandler == nil || serverCfg == nil {
			return
		}

		clientCh, err := protoHandler.AcceptClients(ctx)
		if err != nil {
			D.log.Warn("accept clients failed", "error", err)
			return
		}

		var peers sync.WaitGroup
		defer peers.Wait()
		for client := range clientCh {
			peers.Add(1)
			go func() {
				defer peers.Done()
				if err := D.dispatchPeer(acceptCtx, client, serverCfg, out); err != nil {
					D.log.Warn("relay peer handling failed", "addr", client.Address, "error", err)
				}
			}()
		}
	}()

	return out, nil
}

// relayWatchPlatform watches platform signaling events
func relayWatchPlatform(ctx context.Context, events <-chan platform.Event, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				log.Debug("relay signaling monitor stopped: event stream closed")
				return
			}
			if event.Type == platform.EventCallEnded {
				log.Debug("relay signaling reported call ended", "metadata", event.Metadata)
			}
		}
	}
}

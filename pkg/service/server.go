package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	pb "github.com/theairblow/turnable/pkg/service/proto"
)

// Server manages Turnable server or client instances and exposes management via a custom protocol
type Server struct {
	running   atomic.Bool
	mu        sync.RWMutex
	instances map[string]*Instance

	log   *slog.Logger
	relay *LogRelayHandler

	cfg         config.ServiceConfig
	keyPair     *KeyPair
	allowedKeys [][]byte

	listenersMu sync.Mutex
	listeners   []net.Listener
}

// NewServer creates a new Server instance
func NewServer(cfg *config.ServiceConfig) (*Server, error) {
	var kp *KeyPair
	if cfg.PubKey != "" || cfg.PrivKey != "" {
		var err error
		kp, err = NewKeyPair(cfg.PubKey, cfg.PrivKey)
		if err != nil {
			return nil, fmt.Errorf("parse server keypair: %w", err)
		}
	}

	if len(cfg.AllowedKeys) > 0 && kp == nil {
		return nil, errors.New("allowed client keys require a server keypair")
	}

	allowedKeys := make([][]byte, 0, len(cfg.AllowedKeys))
	for _, k := range cfg.AllowedKeys {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			return nil, fmt.Errorf("decode allowed client key: %w", err)
		}
		allowedKeys = append(allowedKeys, b)
	}

	relay := newLogRelayHandler(slog.Default().Handler())
	common.SetLogHandler(relay)

	return &Server{
		instances:   make(map[string]*Instance),
		log:         slog.Default(),
		relay:       relay,
		keyPair:     kp,
		allowedKeys: allowedKeys,
		cfg:         *cfg,
	}, nil
}

// SetLogger changes the slog logger instance
func (s *Server) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}

	s.log = log
}

// Start starts the service server
func (s *Server) Start() error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	success := false
	defer func() {
		if !success {
			s.running.Store(false)
		}
	}()

	if s.cfg.ListenAddr != "" {
		err := s.listenTCP(s.cfg.ListenAddr)
		if err != nil {
			return err
		}
	}

	if s.cfg.UnixSocket != "" {
		err := s.listenUnix(s.cfg.UnixSocket)
		if err != nil {
			_ = s.Stop()
			return err
		}
	}

	success = true
	return nil
}

// listenTCP accepts service connections on the given TCP address
func (s *Server) listenTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}

	s.listenersMu.Lock()
	s.listeners = append(s.listeners, ln)
	s.listenersMu.Unlock()
	go s.accept(ln)
	return nil
}

// listenUnix accepts service connections on the given Unix socket path
func (s *Server) listenUnix(path string) error {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen unix: %w", err)
	}

	s.listenersMu.Lock()
	s.listeners = append(s.listeners, ln)
	s.listenersMu.Unlock()
	go s.accept(ln)
	return nil
}

// IsRunning returns whether the service server is currently running
func (s *Server) IsRunning() bool {
	return s.running.Load()
}

// Stop closes all listeners and stops all managed instances
func (s *Server) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	s.listenersMu.Lock()
	for _, ln := range s.listeners {
		_ = ln.Close()
	}

	s.listeners = nil
	s.listenersMu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inst := range s.instances {
		_ = inst.Stop()
	}

	return nil
}

// accept accepts incoming connections from a listener and serves each one
func (s *Server) accept(ln net.Listener) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return
		}

		go newClientConn(s, nc).serve()
	}
}

// startServer creates and starts a Turnable server instance
func (s *Server) startServer(req *pb.StartServerRequest) (string, error) {
	srv, err := buildServerInstance(req)
	if err != nil {
		return "", err
	}

	id := uuid.New().String()
	srv.SetLogger(s.log.With("server_id", id))
	if err := srv.Start(); err != nil {
		return "", fmt.Errorf("start server: %w", err)
	}

	s.mu.Lock()
	s.instances[id] = &Instance{ID: id, server: srv}
	s.mu.Unlock()
	return id, nil
}

// startClient creates and starts a Turnable client instance
func (s *Server) startClient(req *pb.StartClientRequest) (string, error) {
	cli, err := buildClientInstance(req)
	if err != nil {
		return "", err
	}

	id := uuid.New().String()
	cli.SetLogger(s.log.With("client_id", id))
	if err := cli.Start(req.ListenAddr); err != nil {
		return "", fmt.Errorf("start client: %w", err)
	}

	s.mu.Lock()
	s.instances[id] = &Instance{ID: id, client: cli}
	s.mu.Unlock()
	return id, nil
}

// stopInstance stops and removes an instance by ID
func (s *Server) stopInstance(id string) error {
	s.mu.Lock()
	inst, ok := s.instances[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("instance %q not found", id)
	}
	delete(s.instances, id)
	s.mu.Unlock()
	return inst.Stop()
}

// updateProvider updates config provider for an instance
func (s *Server) updateProvider(id string, cfg string) error {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}

	return inst.server.Config.ReplaceProvider([]byte(cfg))
}

// listInstances returns info for all managed instances
func (s *Server) listInstances() []*pb.InstanceInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	infos := make([]*pb.InstanceInfo, 0, len(s.instances))
	for _, inst := range s.instances {
		infos = append(infos, inst.Info())
	}
	return infos
}

// clientConn handles a single service client connection
type clientConn struct {
	svc     *Server
	nc      net.Conn
	remote  net.Addr
	writeCh chan *pb.Response
}

// newClientConn allocates a clientConn for an incoming connection
func newClientConn(svc *Server, nc net.Conn) *clientConn {
	return &clientConn{
		svc:     svc,
		nc:      nc,
		remote:  nc.RemoteAddr(),
		writeCh: make(chan *pb.Response, 64),
	}
}

// serve performs the handshake, subscribes to logs, then runs the IO loops
func (c *clientConn) serve() {
	defer c.nc.Close()

	c.svc.log.Debug("client initiating handshake", "remote", c.remote)

	wrapped, pubKey, err := serverHandshake(c.nc, c.svc.keyPair, c.svc.allowedKeys)
	if err != nil {
		c.svc.log.Warn("service handshake failed", "remote", c.remote, "error", err)
		return
	}
	c.nc = wrapped

	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey)
	c.svc.log.Info("client connected", "remote", c.remote, "pubkey", pubKeyB64)
	defer func() {
		c.svc.relay.broadcast.unsubscribe(c)
		c.svc.log.Info("client disconnected", "remote", c.remote, "pubkey", pubKeyB64)
	}()

	c.svc.relay.broadcast.subscribe(c)
	go c.writeLoop()
	c.readLoop()
}

// readLoop reads and dispatches requests until the connection closes
func (c *clientConn) readLoop() {
	defer close(c.writeCh)
	for {
		var req pb.Request
		if err := readFramed(c.nc, &req); err != nil {
			return
		}

		resp, err := c.dispatch(&req)
		if err != nil {
			c.sendErr(err)
			return
		}

		if resp != nil {
			c.writeCh <- resp
		}
	}
}

// writeLoop drains channel and sends responses to the client
func (c *clientConn) writeLoop() {
	defer c.nc.Close()
	for resp := range c.writeCh {
		if err := writeFramed(c.nc, resp); err != nil {
			return
		}
	}
}

// sendLog enqueues a log record without blocking
func (c *clientConn) sendLog(rec *pb.LogRecord) {
	select {
	case c.writeCh <- &pb.Response{Payload: &pb.Response_LogRecord{LogRecord: rec}}:
	default:
	}
}

// sendErr sends a fatal ErrorResponse
func (c *clientConn) sendErr(err error) {
	_ = writeFramed(c.nc, &pb.Response{Payload: &pb.Response_Error{Error: &pb.ErrorResponse{Message: err.Error()}}})
}

// dispatch handles an incoming request and sends a response
func (c *clientConn) dispatch(req *pb.Request) (*pb.Response, error) {
	switch p := req.Payload.(type) {
	case *pb.Request_StartServer:
		id, err := c.svc.startServer(p.StartServer)
		resp := &pb.StartServerResponse{InstanceId: id}
		if err != nil {
			c.svc.log.Warn("failed to start server instance", "remote", c.remote, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("started server instance", "remote", c.remote, "id", id)
		}

		return &pb.Response{Payload: &pb.Response_StartServer{StartServer: resp}}, nil
	case *pb.Request_StartClient:
		id, err := c.svc.startClient(p.StartClient)
		resp := &pb.StartClientResponse{InstanceId: id}
		if err != nil {
			c.svc.log.Warn("failed to start client instance", "remote", c.remote, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("started client instance", "remote", c.remote, "id", id)
		}

		return &pb.Response{Payload: &pb.Response_StartClient{StartClient: resp}}, nil
	case *pb.Request_StopInstance:
		resp := &pb.StopInstanceResponse{}
		if err := c.svc.stopInstance(p.StopInstance.InstanceId); err != nil {
			c.svc.log.Warn("failed to stop instance", "remote", c.remote, "id", p.StopInstance.InstanceId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("stopped instance", "remote", c.remote, "id", p.StopInstance.InstanceId)
		}

		return &pb.Response{Payload: &pb.Response_StopInstance{StopInstance: resp}}, nil
	case *pb.Request_UpdateProvider:
		if err := c.svc.updateProvider(p.UpdateProvider.InstanceId, p.UpdateProvider.ProviderConfig); err != nil {
			c.svc.log.Warn("failed to update provider", "remote", c.remote, "id", p.UpdateProvider.InstanceId, "error", err)
			return nil, err
		}

		c.svc.log.Info("updated provider", "remote", c.remote, "id", p.UpdateProvider.InstanceId)
		return &pb.Response{Payload: &pb.Response_UpdateProvider{UpdateProvider: &pb.UpdateProviderResponse{}}}, nil
	case *pb.Request_ListInstances:
		c.svc.log.Debug("listed instances", "remote", c.remote)
		return &pb.Response{Payload: &pb.Response_ListInstances{ListInstances: &pb.ListInstancesResponse{
			Instances: c.svc.listInstances(),
		}}}, nil
	case *pb.Request_ValidateServerConfig:
		c.svc.log.Debug("validated server config", "remote", c.remote)
		return &pb.Response{Payload: &pb.Response_ValidateServerConfig{
			ValidateServerConfig: handleValidateServerConfig(p.ValidateServerConfig),
		}}, nil
	case *pb.Request_ValidateClientConfig:
		c.svc.log.Debug("validated client config", "remote", c.remote)
		return &pb.Response{Payload: &pb.Response_ValidateClientConfig{
			ValidateClientConfig: handleValidateClientConfig(p.ValidateClientConfig),
		}}, nil
	case *pb.Request_ConvertClientConfig:
		resp, err := handleConvertClientConfig(p.ConvertClientConfig)
		if err != nil {
			return nil, err
		}

		c.svc.log.Debug("converted client config", "remote", c.remote)
		return &pb.Response{Payload: &pb.Response_ConvertClientConfig{ConvertClientConfig: resp}}, nil
	default:
		return nil, fmt.Errorf("unknown request type")
	}
}

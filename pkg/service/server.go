package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
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

	persistDir string

	listenersMu sync.Mutex
	listeners   []net.Listener
}

// persistRecord is the on-disk representation of a persisted instance
type persistRecord struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Config      string   `json:"config"`
	ListenAddrs []string `json:"listen_addrs,omitempty"`
	Autostart   bool     `json:"autostart"`
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
		persistDir:  cfg.PersistDir,
	}, nil
}

// SetLogger changes the slog logger instance
func (s *Server) SetLogger(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}

	s.log = log
}

// SetPersistDir overrides the persistence directory
func (s *Server) SetPersistDir(dir string) {
	s.persistDir = dir
}

// Start starts the service server and restores persisted instances
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

	if s.persistDir != "" {
		s.loadPersistedInstances()
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

// resolveInstanceID returns the provided ID if non-empty, otherwise generates a new UUID
func resolveInstanceID(provided string) string {
	provided = strings.TrimSpace(provided)
	if provided != "" {
		return provided
	}
	return uuid.New().String()
}

// resolveInstanceName returns the provided name if non-empty, otherwise "Unnamed"
func resolveInstanceName(provided string) string {
	provided = strings.TrimSpace(provided)
	if provided != "" {
		return provided
	}
	return "Unnamed"
}

// startServer creates and starts a Turnable server instance
func (s *Server) startServer(req *pb.StartServerRequest) (string, error) {
	id := resolveInstanceID(req.InstanceId)
	name := resolveInstanceName(req.Name)

	s.mu.RLock()
	_, exists := s.instances[id]
	s.mu.RUnlock()
	if exists {
		return "", fmt.Errorf("instance %q already exists", id)
	}

	srv, err := buildServerInstance(req)
	if err != nil {
		return "", err
	}

	inst := &Instance{ID: id, Name: name, config: req.Config, server: srv, Autostart: req.Autostart}

	s.mu.Lock()
	s.instances[id] = inst
	s.mu.Unlock()

	if s.persistDir != "" {
		s.savePersisted(inst)
	}

	s.broadcastEvent(&pb.InstanceEvent{
		InstanceId:   id,
		Name:         name,
		InstanceType: pb.InstanceType_INSTANCE_TYPE_SERVER,
		EventType:    pb.InstanceEventType_INSTANCE_EVENT_TYPE_CREATED,
	})

	go func() {
		srv.SetLogger(s.log.With("server_id", id))

		inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STARTING)

		if err := srv.Start(); err != nil {
			s.log.Warn("server start failed", "client_id", id, "error", err)
			s.broadcastEvent(&pb.InstanceEvent{
				InstanceId:   id,
				Name:         name,
				InstanceType: pb.InstanceType_INSTANCE_TYPE_SERVER,
				EventType:    pb.InstanceEventType_INSTANCE_EVENT_TYPE_FAILED,
			})

			return
		}

		inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STARTED)
		s.broadcastEvent(&pb.InstanceEvent{
			InstanceId:   id,
			Name:         name,
			InstanceType: pb.InstanceType_INSTANCE_TYPE_SERVER,
			EventType:    pb.InstanceEventType_INSTANCE_EVENT_TYPE_STARTED,
		})
	}()

	return id, nil
}

// startClient creates and starts a Turnable client instance
func (s *Server) startClient(req *pb.StartClientRequest) (string, error) {
	id := resolveInstanceID(req.InstanceId)
	name := resolveInstanceName(req.Name)

	s.mu.RLock()
	_, exists := s.instances[id]
	s.mu.RUnlock()
	if exists {
		return "", fmt.Errorf("instance %q already exists", id)
	}

	cli, err := buildClientInstance(req)
	if err != nil {
		return "", err
	}

	inst := &Instance{ID: id, Name: name, config: req.Config, listenAddrs: req.ListenAddrs, client: cli, Autostart: req.Autostart}
	s.mu.Lock()
	s.instances[id] = inst
	s.mu.Unlock()

	if s.persistDir != "" {
		s.savePersisted(inst)
	}

	s.broadcastEvent(&pb.InstanceEvent{
		InstanceId:   id,
		Name:         name,
		InstanceType: pb.InstanceType_INSTANCE_TYPE_CLIENT,
		EventType:    pb.InstanceEventType_INSTANCE_EVENT_TYPE_CREATED,
	})

	go func() {
		cli.SetLogger(s.log.With("client_id", id))
		inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STARTING)

		if err := cli.Start(req.ListenAddrs); err != nil {
			s.log.Warn("client start failed", "client_id", id, "error", err)
			inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_FAILED)
			s.broadcastEvent(&pb.InstanceEvent{
				InstanceId:   id,
				Name:         name,
				InstanceType: pb.InstanceType_INSTANCE_TYPE_CLIENT,
				EventType:    pb.InstanceEventType_INSTANCE_EVENT_TYPE_FAILED,
			})

			return
		}

		inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STARTED)
		s.broadcastEvent(&pb.InstanceEvent{
			InstanceId:   id,
			Name:         name,
			InstanceType: pb.InstanceType_INSTANCE_TYPE_CLIENT,
			EventType:    pb.InstanceEventType_INSTANCE_EVENT_TYPE_STARTED,
		})
	}()

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

	if s.persistDir != "" {
		s.deletePersisted(id)
	}

	err := inst.Stop()
	inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STOPPED)

	itype := pb.InstanceType_INSTANCE_TYPE_CLIENT
	if inst.server != nil {
		itype = pb.InstanceType_INSTANCE_TYPE_SERVER
	}

	s.broadcastEvent(&pb.InstanceEvent{
		InstanceId:   id,
		Name:         inst.Name,
		InstanceType: itype,
		EventType:    pb.InstanceEventType_INSTANCE_EVENT_TYPE_STOPPED,
	})

	return err
}

// updateProvider updates config provider for an instance and persists the change
func (s *Server) updateProvider(id string, cfg string) error {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}

	if err := inst.server.Config.ReplaceProvider([]byte(cfg)); err != nil {
		return err
	}

	updated, err := inst.server.Config.ToJSON(false)
	if err == nil {
		inst.config = updated
		if s.persistDir != "" {
			s.savePersisted(inst)
		}
	}

	return nil
}

// addRoute adds or updates a route on a server instance
func (s *Server) addRoute(id string, routeJSON string) error {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}

	if inst.server == nil {
		return fmt.Errorf("instance %q is not a server instance", id)
	}

	var route config.Route
	if err := json.Unmarshal([]byte(routeJSON), &route); err != nil {
		return fmt.Errorf("parse route JSON: %w", err)
	}

	if err := route.Validate(); err != nil {
		return fmt.Errorf("validate route: %w", err)
	}

	if err := inst.server.Config.AddRoute(&route); err != nil {
		return err
	}

	s.persistAndNotifyProvider(inst)
	return nil
}

// deleteRoute removes a route from a server instance
func (s *Server) deleteRoute(id string, routeID string) error {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}

	if inst.server == nil {
		return fmt.Errorf("instance %q is not a server instance", id)
	}

	if err := inst.server.Config.DeleteRoute(routeID); err != nil {
		return err
	}

	s.persistAndNotifyProvider(inst)
	return nil
}

// addUser adds or updates a user on a server instance
func (s *Server) addUser(id string, userJSON string) error {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}

	if inst.server == nil {
		return fmt.Errorf("instance %q is not a server instance", id)
	}

	var user config.User
	if err := json.Unmarshal([]byte(userJSON), &user); err != nil {
		return fmt.Errorf("parse user JSON: %w", err)
	}

	if user.UUID == "" {
		return fmt.Errorf("user uuid is required")
	}

	if err := inst.server.Config.AddUser(&user); err != nil {
		return err
	}

	s.persistAndNotifyProvider(inst)
	return nil
}

// deleteUser removes a user from a server instance
func (s *Server) deleteUser(id string, userUUID string) error {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}

	if inst.server == nil {
		return fmt.Errorf("instance %q is not a server instance", id)
	}

	if err := inst.server.Config.DeleteUser(userUUID); err != nil {
		return err
	}

	s.persistAndNotifyProvider(inst)
	return nil
}

// updateMetadata updates instance metadata like name and autostart toggle
func (s *Server) updateMetadata(id, name string, autostart bool) error {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}

	if name != "" {
		inst.Name = name
	}
	inst.Autostart = autostart

	if s.persistDir != "" {
		s.savePersisted(inst)
	}

	s.broadcastEvent(&pb.InstanceEvent{
		InstanceId: id,
		Name:       inst.Name,
		InstanceType: func() pb.InstanceType {
			if inst.server != nil {
				return pb.InstanceType_INSTANCE_TYPE_SERVER
			}
			return pb.InstanceType_INSTANCE_TYPE_CLIENT
		}(),
		EventType: pb.InstanceEventType_INSTANCE_EVENT_TYPE_UPDATED,
	})

	return nil
}

// persistAndNotifyProvider persists the instance config and broadcasts an UPDATED event
func (s *Server) persistAndNotifyProvider(inst *Instance) {
	if inst.server.Config.ProviderID() == "raw" {
		updated, err := inst.server.Config.ToJSON(false)
		if err == nil {
			inst.config = updated
			if s.persistDir != "" {
				s.savePersisted(inst)
			}
		} else {
			s.log.Warn("failed to serialize config", "id", inst.ID, "error", err)
		}
	}

	s.broadcastEvent(&pb.InstanceEvent{
		InstanceId:   inst.ID,
		Name:         inst.Name,
		InstanceType: pb.InstanceType_INSTANCE_TYPE_SERVER,
		EventType:    pb.InstanceEventType_INSTANCE_EVENT_TYPE_UPDATED,
	})
}

// broadcastEvent sends an InstanceEvent to all connected service clients
func (s *Server) broadcastEvent(event *pb.InstanceEvent) {
	s.relay.broadcast.mu.RLock()
	defer s.relay.broadcast.mu.RUnlock()
	for c := range s.relay.broadcast.subs {
		c.sendInstanceEvent(event)
	}
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

// getInstance returns the full details for a single instance
func (s *Server) getInstance(id string) *pb.GetInstanceResponse {
	s.mu.RLock()
	inst, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return &pb.GetInstanceResponse{Error: fmt.Sprintf("instance %q not found", id)}
	}

	return &pb.GetInstanceResponse{
		Info:        inst.Info(),
		Config:      inst.config,
		ListenAddrs: inst.listenAddrs,
	}
}

// savePersisted writes an instance record to the persist directory
func (s *Server) savePersisted(inst *Instance) {
	if err := os.MkdirAll(s.persistDir, 0o750); err != nil {
		s.log.Warn("persist: failed to create persist dir", "dir", s.persistDir, "error", err)
		return
	}

	rec := persistRecord{
		ID:          inst.ID,
		Name:        inst.Name,
		Autostart:   inst.Autostart,
		Config:      inst.config,
		ListenAddrs: inst.listenAddrs,
	}
	if inst.server != nil {
		rec.Type = "server"
	} else {
		rec.Type = "client"
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		s.log.Warn("persist: failed to marshal record", "id", inst.ID, "error", err)
		return
	}

	path := filepath.Join(s.persistDir, inst.ID+".json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		s.log.Warn("persist: failed to write record", "path", path, "error", err)
	}
}

// deletePersisted removes a persisted instance record from disk
func (s *Server) deletePersisted(id string) {
	path := filepath.Join(s.persistDir, id+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		s.log.Warn("persist: failed to remove record", "path", path, "error", err)
	}
}

// loadPersistedInstances reads all records from the persist dir and restores them
func (s *Server) loadPersistedInstances() {
	entries, err := os.ReadDir(s.persistDir)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Warn("persist: failed to read persist dir", "dir", s.persistDir, "error", err)
		}
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(s.persistDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			s.log.Warn("persist: failed to read record", "path", path, "error", err)
			continue
		}

		var rec persistRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			s.log.Warn("persist: failed to parse record", "path", path, "error", err)
			continue
		}

		if !rec.Autostart {
			continue
		}

		switch rec.Type {
		case "server":
			_, err = s.startServer(&pb.StartServerRequest{
				Config:     rec.Config,
				InstanceId: rec.ID,
				Name:       rec.Name,
				Autostart:  rec.Autostart,
			})
		case "client":
			_, err = s.startClient(&pb.StartClientRequest{
				Config:      rec.Config,
				ListenAddrs: rec.ListenAddrs,
				InstanceId:  rec.ID,
				Name:        rec.Name,
				Autostart:   rec.Autostart,
			})
		default:
			s.log.Warn("persist: unknown instance type in record", "path", path, "type", rec.Type)
			continue
		}

		if err != nil {
			s.log.Warn("persist: failed to restore instance", "id", rec.ID, "error", err)
		} else {
			s.log.Info("persist: restored instance", "id", rec.ID, "name", rec.Name, "type", rec.Type)
		}
	}
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

// sendInstanceEvent enqueues an InstanceEvent without blocking
func (c *clientConn) sendInstanceEvent(event *pb.InstanceEvent) {
	select {
	case c.writeCh <- &pb.Response{Payload: &pb.Response_InstanceEvent{InstanceEvent: event}}:
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
	case *pb.Request_GetInstance:
		resp := c.svc.getInstance(p.GetInstance.InstanceId)
		if resp.Error != "" {
			c.svc.log.Warn("get instance failed", "remote", c.remote, "id", p.GetInstance.InstanceId, "error", resp.Error)
		} else {
			c.svc.log.Debug("fetched instance", "remote", c.remote, "id", p.GetInstance.InstanceId)
		}

		return &pb.Response{Payload: &pb.Response_GetInstance{GetInstance: resp}}, nil
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
	case *pb.Request_AddRoute:
		resp := &pb.AddRouteResponse{}
		if err := c.svc.addRoute(p.AddRoute.InstanceId, p.AddRoute.RouteJson); err != nil {
			c.svc.log.Warn("failed to add route", "remote", c.remote, "id", p.AddRoute.InstanceId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("added route", "remote", c.remote, "id", p.AddRoute.InstanceId)
		}
		return &pb.Response{Payload: &pb.Response_AddRoute{AddRoute: resp}}, nil
	case *pb.Request_DeleteRoute:
		resp := &pb.DeleteRouteResponse{}
		if err := c.svc.deleteRoute(p.DeleteRoute.InstanceId, p.DeleteRoute.RouteId); err != nil {
			c.svc.log.Warn("failed to delete route", "remote", c.remote, "id", p.DeleteRoute.InstanceId, "route", p.DeleteRoute.RouteId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("deleted route", "remote", c.remote, "id", p.DeleteRoute.InstanceId, "route", p.DeleteRoute.RouteId)
		}

		return &pb.Response{Payload: &pb.Response_DeleteRoute{DeleteRoute: resp}}, nil
	case *pb.Request_AddUser:
		resp := &pb.AddUserResponse{}
		if err := c.svc.addUser(p.AddUser.InstanceId, p.AddUser.UserJson); err != nil {
			c.svc.log.Warn("failed to add user", "remote", c.remote, "id", p.AddUser.InstanceId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("added user", "remote", c.remote, "id", p.AddUser.InstanceId)
		}

		return &pb.Response{Payload: &pb.Response_AddUser{AddUser: resp}}, nil
	case *pb.Request_DeleteUser:
		resp := &pb.DeleteUserResponse{}
		if err := c.svc.deleteUser(p.DeleteUser.InstanceId, p.DeleteUser.UserUuid); err != nil {
			c.svc.log.Warn("failed to delete user", "remote", c.remote, "id", p.DeleteUser.InstanceId, "uuid", p.DeleteUser.UserUuid, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("deleted user", "remote", c.remote, "id", p.DeleteUser.InstanceId, "uuid", p.DeleteUser.UserUuid)
		}

		return &pb.Response{Payload: &pb.Response_DeleteUser{DeleteUser: resp}}, nil
	case *pb.Request_UpdateMetadata:
		resp := &pb.UpdateMetadataResponse{}
		if err := c.svc.updateMetadata(p.UpdateMetadata.InstanceId, p.UpdateMetadata.Name, p.UpdateMetadata.Autostart); err != nil {
			c.svc.log.Warn("failed to update metadata", "remote", c.remote, "id", p.UpdateMetadata.InstanceId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("updated metadata", "remote", c.remote, "id", p.UpdateMetadata.InstanceId)
		}

		return &pb.Response{Payload: &pb.Response_UpdateMetadata{UpdateMetadata: resp}}, nil
	default:
		return nil, fmt.Errorf("unknown request type")
	}
}

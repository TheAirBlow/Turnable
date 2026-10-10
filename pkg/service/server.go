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
	"time"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	pb "github.com/theairblow/turnable/pkg/service/proto"
)

// Server manages Turnable server or client instances and exposes management via a custom protocol
type Server struct {
	running atomic.Bool  // service is running
	mu      sync.RWMutex // guards instances and providers

	instances map[string]*Instance        // instances by ID
	providers map[string]*ManagedProvider // providers by UUID

	log   *slog.Logger     // logger
	relay *LogRelayHandler // forwards logs to subscribed clients

	cfg         config.ServiceConfig // service config
	keyPair     *KeyPair             // service key pair
	allowedKeys [][]byte             // public keys allowed to connect

	persistDir string // directory for persisted state

	listenersMu sync.Mutex     // guards listeners
	listeners   []net.Listener // open control listeners
}

// ManagedProvider represents a provider with metadata
type ManagedProvider struct {
	UUID     string             // Unique UUID of this provider
	Name     string             // Display name
	Provider providers.Provider // Running provider
	Config   string             // Provider config JSON
}

// eventSendTimeout is how long an instance event may wait for space in a client's write queue
const eventSendTimeout = 5 * time.Second

// providersDir is the persist subdirectory holding provider records
const providersDir = "providers"

// persistProviderRecord is the on-disk representation of a persisted provider
type persistProviderRecord struct {
	UUID   string          `json:"uuid"`   // Provider UUID
	Name   string          `json:"name"`   // Display name
	Config json.RawMessage `json:"config"` // Provider config
}

// CurrentConfig returns the provider's live config, falling back to the config it was created with
func (mp *ManagedProvider) CurrentConfig() string {
	data, err := mp.Provider.ToJSON()
	if err != nil {
		return mp.Config
	}
	return string(data)
}

// persistRecord is the on-disk representation of a persisted instance
type persistRecord struct {
	ID           string   `json:"id"`                      // Instance ID
	Name         string   `json:"name"`                    // Display name
	Type         string   `json:"type"`                    // Instance type
	Config       string   `json:"config"`                  // Instance config
	ListenAddrs  []string `json:"listen_addrs,omitempty"`  // Listen addresses
	Autostart    bool     `json:"autostart"`               // Start with the service
	ProviderUUID string   `json:"provider_uuid,omitempty"` // UUID of the provider used
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
		providers:   make(map[string]*ManagedProvider),
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
		s.loadPersistedProviders()
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
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			return fmt.Errorf("listen unix: %s is already in use", path)
		}
		_ = os.Remove(path)
	}

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
	for _, mp := range s.providers {
		_ = mp.Provider.Stop()
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
func resolveInstanceID(provided string) (string, error) {
	provided = strings.TrimSpace(provided)
	if provided == "" {
		return uuid.New().String(), nil
	}

	if err := validateID(provided); err != nil {
		return "", fmt.Errorf("invalid instance id: %w", err)
	}

	return provided, nil
}

// validateID ensures an ID is safe to use as a persisted file name
func validateID(id string) error {
	if id == "." || id == ".." || strings.ContainsAny(id, `/\`) || strings.ContainsRune(id, 0) {
		return fmt.Errorf("%q is not allowed", id)
	}
	return nil
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
func (s *Server) startServer(req *pb.StartServerRequest, providerUUID string) (string, error) {
	id, err := resolveInstanceID(req.InstanceId)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	_, exists := s.instances[id]
	managedProv, providerExists := s.providers[providerUUID]
	s.mu.RUnlock()
	if exists {
		return "", fmt.Errorf("instance %q already exists", id)
	}
	if !providerExists {
		return "", fmt.Errorf("provider with UUID %q not found", providerUUID)
	}

	srv, err := buildServerInstance(req, managedProv.Provider)
	if err != nil {
		return "", err
	}

	inst := &Instance{
		ID:           id,
		Name:         resolveInstanceName(req.Name),
		Autostart:    req.Autostart,
		config:       req.Config,
		server:       srv,
		ProviderUUID: providerUUID,
		provider:     managedProv.Provider,
	}

	srv.SetLogger(s.log.With("server_id", id))
	return id, s.addInstance(inst)
}

// startClient creates and starts a Turnable client instance
func (s *Server) startClient(req *pb.StartClientRequest) (string, error) {
	id, err := resolveInstanceID(req.InstanceId)
	if err != nil {
		return "", err
	}

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

	inst := &Instance{
		ID:          id,
		Name:        resolveInstanceName(req.Name),
		Autostart:   req.Autostart,
		config:      req.Config,
		listenAddrs: req.ListenAddrs,
		client:      cli,
	}

	cli.SetLogger(s.log.With("client_id", id))
	return id, s.addInstance(inst)
}

// addInstance registers, persists and asynchronously starts an instance
func (s *Server) addInstance(inst *Instance) error {
	s.mu.Lock()
	if _, exists := s.instances[inst.ID]; exists {
		s.mu.Unlock()
		return fmt.Errorf("instance %q already exists", inst.ID)
	}
	if inst.ProviderUUID != "" {
		if _, ok := s.providers[inst.ProviderUUID]; !ok {
			s.mu.Unlock()
			return fmt.Errorf("provider with UUID %q not found", inst.ProviderUUID)
		}
	}
	s.instances[inst.ID] = inst
	s.mu.Unlock()

	if s.persistDir != "" {
		s.savePersisted(inst)
	}

	inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STARTING)
	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_CREATED)

	go s.runInstance(inst)
	return nil
}

// runInstance starts an instance and tracks its state until it stops
func (s *Server) runInstance(inst *Instance) {
	if err := inst.Start(); err != nil {
		if errors.Is(err, errInstanceStopped) {
			return
		}

		s.log.Warn("instance start failed", "id", inst.ID, "error", err)
		s.failInstance(inst)
		return
	}

	if inst.server != nil {
		go s.forwardSessionEvents(inst)
		s.setInstanceStatus(inst, pb.InstanceStatus_INSTANCE_STATUS_STARTED, pb.InstanceEventType_INSTANCE_EVENT_TYPE_STARTED)
		return
	}

	// Clients count as started only while the tunnel is actually connected
	for ev := range inst.client.Events() {
		if ev.Connected {
			s.setInstanceStatus(inst, pb.InstanceStatus_INSTANCE_STATUS_STARTED, pb.InstanceEventType_INSTANCE_EVENT_TYPE_STARTED)
		} else {
			s.setInstanceStatus(inst, pb.InstanceStatus_INSTANCE_STATUS_STARTING, pb.InstanceEventType_INSTANCE_EVENT_TYPE_UPDATED)
		}
	}

	s.log.Warn("client instance stopped unexpectedly", "id", inst.ID)
	s.failInstance(inst)
}

// setInstanceStatus updates a live instance's status and broadcasts the event if it changed
func (s *Server) setInstanceStatus(inst *Instance, status pb.InstanceStatus, event pb.InstanceEventType) {
	if inst.Stopped() || inst.GetStatus() == status {
		return
	}

	inst.SetStatus(status)
	s.emitEvent(inst, event)
}

// failInstance marks a live instance as failed and broadcasts the event
func (s *Server) failInstance(inst *Instance) {
	if inst.Stopped() {
		return
	}

	inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_FAILED)
	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_FAILED)
}

// emitEvent broadcasts an InstanceEvent of the given type for an instance
func (s *Server) emitEvent(inst *Instance, event pb.InstanceEventType) {
	s.broadcastEvent(&pb.InstanceEvent{
		InstanceId:   inst.ID,
		Name:         inst.Name,
		InstanceType: inst.Type(),
		EventType:    event,
	})
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
	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_STOPPED)

	return err
}

// persistInstance persists the instance config to disk
func (s *Server) persistInstance(inst *Instance) {
	if s.persistDir != "" {
		s.savePersisted(inst)
	}

	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_UPDATED)
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
		ID:           inst.ID,
		Name:         inst.Name,
		Autostart:    inst.Autostart,
		Config:       inst.config,
		ListenAddrs:  inst.listenAddrs,
		ProviderUUID: inst.ProviderUUID,
		Type:         "client",
	}
	if inst.server != nil {
		rec.Type = "server"
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

// persistProvider saves a provider record if persistence is enabled
func (s *Server) persistProvider(mp *ManagedProvider) {
	if s.persistDir != "" {
		s.saveProvider(mp)
	}
}

// saveProvider writes a provider record with its current config to the persist directory
func (s *Server) saveProvider(mp *ManagedProvider) {
	dir := filepath.Join(s.persistDir, providersDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		s.log.Warn("persist: failed to create providers dir", "dir", dir, "error", err)
		return
	}

	data, err := json.MarshalIndent(persistProviderRecord{
		UUID:   mp.UUID,
		Name:   mp.Name,
		Config: json.RawMessage(mp.CurrentConfig()),
	}, "", "  ")
	if err != nil {
		s.log.Warn("persist: failed to marshal provider record", "uuid", mp.UUID, "error", err)
		return
	}

	path := filepath.Join(dir, mp.UUID+".json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		s.log.Warn("persist: failed to write provider record", "path", path, "error", err)
	}
}

// deletePersistedProvider removes a persisted provider record from disk
func (s *Server) deletePersistedProvider(uuid string) {
	path := filepath.Join(s.persistDir, providersDir, uuid+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		s.log.Warn("persist: failed to remove provider record", "path", path, "error", err)
	}
}

// loadPersistedProviders reads all provider records from the persist dir and restores them
func (s *Server) loadPersistedProviders() {
	dir := filepath.Join(s.persistDir, providersDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Warn("persist: failed to read providers dir", "dir", dir, "error", err)
		}
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			s.log.Warn("persist: failed to read provider record", "path", path, "error", err)
			continue
		}

		var rec persistProviderRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			s.log.Warn("persist: failed to parse provider record", "path", path, "error", err)
			continue
		}

		if _, err := s.addProvider(rec.UUID, rec.Name, string(rec.Config)); err != nil {
			s.log.Warn("persist: failed to restore provider", "uuid", rec.UUID, "error", err)
		} else {
			s.log.Info("persist: restored provider", "uuid", rec.UUID, "name", rec.Name)
		}
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

		// Skip restoration if autostart is disabled
		if !rec.Autostart {
			s.log.Debug("persist: skipping instance with autostart disabled", "id", rec.ID, "name", rec.Name)
			continue
		}

		switch rec.Type {
		case "server":
			_, err = s.startServer(&pb.StartServerRequest{
				Config:       rec.Config,
				InstanceId:   rec.ID,
				Name:         rec.Name,
				Autostart:    rec.Autostart,
				ProviderUuid: rec.ProviderUUID,
			}, rec.ProviderUUID)
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
	svc     *Server           // owning service
	nc      net.Conn          // client connection
	remote  net.Addr          // client address
	writeCh chan *pb.Response // responses waiting to be written
	done    chan struct{}     // closed when the connection ends
}

// newClientConn allocates a clientConn for an incoming connection
func newClientConn(svc *Server, nc net.Conn) *clientConn {
	return &clientConn{
		svc:     svc,
		nc:      nc,
		remote:  nc.RemoteAddr(),
		writeCh: make(chan *pb.Response, 256),
		done:    make(chan struct{}),
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
	c.svc.relay.broadcast.subscribe(c)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writeLoop()
	}()

	c.readLoop()

	c.svc.relay.broadcast.unsubscribe(c)
	close(c.writeCh)
	<-writerDone
	c.svc.log.Info("client disconnected", "remote", c.remote, "pubkey", pubKeyB64)
}

// readLoop reads and dispatches requests until the connection closes
func (c *clientConn) readLoop() {
	for {
		var req pb.Request
		if err := readFramed(c.nc, &req); err != nil {
			return
		}

		resp, err := c.dispatch(&req)
		if err != nil {
			resp = &pb.Response{Payload: &pb.Response_Error{Error: &pb.ErrorResponse{Message: err.Error()}}}
		}

		if resp != nil && !c.send(resp) {
			return
		}

		if err != nil {
			return
		}
	}
}

// send enqueues a response, blocking until it is queued or the writer has exited
func (c *clientConn) send(resp *pb.Response) bool {
	select {
	case c.writeCh <- resp:
		return true
	case <-c.done:
		return false
	}
}

// writeLoop drains channel and sends responses to the client
func (c *clientConn) writeLoop() {
	defer c.nc.Close()
	defer close(c.done)
	for resp := range c.writeCh {
		if err := writeFramed(c.nc, resp); err != nil {
			return
		}

		if resp.GetError() != nil {
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

// sendInstanceEvent enqueues an InstanceEvent, waiting a bounded time for queue space so state changes aren't dropped
func (c *clientConn) sendInstanceEvent(event *pb.InstanceEvent) {
	timer := time.NewTimer(eventSendTimeout)
	defer timer.Stop()

	select {
	case c.writeCh <- &pb.Response{Payload: &pb.Response_InstanceEvent{InstanceEvent: event}}:
	case <-c.done:
	case <-timer.C:
		c.svc.log.Warn("dropped instance event for slow client", "remote", c.remote, "id", event.InstanceId)
	}
}

// dispatch handles an incoming request and sends a response
func (c *clientConn) dispatch(req *pb.Request) (*pb.Response, error) {
	switch p := req.Payload.(type) {
	case *pb.Request_StartServer:
		id, err := c.svc.startServer(p.StartServer, p.StartServer.ProviderUuid)
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
			c.svc.log.Warn("failed to convert client config", "remote", c.remote, "error", err)
			resp = &pb.ConvertClientConfigResponse{Error: err.Error()}
		} else {
			c.svc.log.Debug("converted client config", "remote", c.remote)
		}

		return &pb.Response{Payload: &pb.Response_ConvertClientConfig{ConvertClientConfig: resp}}, nil
	case *pb.Request_AddProvider:
		resp := &pb.AddProviderResponse{}
		uuid, err := c.svc.addProvider(p.AddProvider.Uuid, p.AddProvider.Name, p.AddProvider.Config)
		if err != nil {
			c.svc.log.Warn("failed to add provider", "remote", c.remote, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("added provider", "remote", c.remote, "uuid", uuid)
			resp.Uuid = uuid
		}

		return &pb.Response{Payload: &pb.Response_AddProvider{AddProvider: resp}}, nil
	case *pb.Request_GetProvider:
		resp := c.svc.getProvider(p.GetProvider.Uuid)
		if resp.Error != "" {
			c.svc.log.Warn("get provider failed", "remote", c.remote, "uuid", p.GetProvider.Uuid, "error", resp.Error)
		} else {
			c.svc.log.Debug("fetched provider", "remote", c.remote, "uuid", p.GetProvider.Uuid)
		}

		return &pb.Response{Payload: &pb.Response_GetProvider{GetProvider: resp}}, nil
	case *pb.Request_ListProviders:
		c.svc.log.Debug("listed providers", "remote", c.remote)
		return &pb.Response{Payload: &pb.Response_ListProviders{ListProviders: &pb.ListProvidersResponse{
			Providers: c.svc.listProviders(),
		}}}, nil
	case *pb.Request_DeleteProvider:
		resp := &pb.DeleteProviderResponse{}
		if err := c.svc.deleteProvider(p.DeleteProvider.Uuid); err != nil {
			c.svc.log.Warn("failed to delete provider", "remote", c.remote, "uuid", p.DeleteProvider.Uuid, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("deleted provider", "remote", c.remote, "uuid", p.DeleteProvider.Uuid)
		}

		return &pb.Response{Payload: &pb.Response_DeleteProvider{DeleteProvider: resp}}, nil
	case *pb.Request_ValidateProviderConfig:
		c.svc.log.Debug("validated provider config", "remote", c.remote)
		return &pb.Response{Payload: &pb.Response_ValidateProviderConfig{
			ValidateProviderConfig: handleValidateProviderConfig(p.ValidateProviderConfig),
		}}, nil
	case *pb.Request_AddProviderRoute:
		resp := &pb.AddProviderRouteResponse{}
		if err := c.svc.addProviderRoute(p.AddProviderRoute.ProviderUuid, p.AddProviderRoute.Route); err != nil {
			c.svc.log.Warn("failed to add provider route", "remote", c.remote, "provider", p.AddProviderRoute.ProviderUuid, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("added provider route", "remote", c.remote, "provider", p.AddProviderRoute.ProviderUuid, "route", p.AddProviderRoute.Route.GetId())
		}
		return &pb.Response{Payload: &pb.Response_AddProviderRoute{AddProviderRoute: resp}}, nil
	case *pb.Request_DeleteProviderRoute:
		resp := &pb.DeleteProviderRouteResponse{}
		if err := c.svc.deleteProviderRoute(p.DeleteProviderRoute.ProviderUuid, p.DeleteProviderRoute.RouteId); err != nil {
			c.svc.log.Warn("failed to delete provider route", "remote", c.remote, "provider", p.DeleteProviderRoute.ProviderUuid, "route", p.DeleteProviderRoute.RouteId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("deleted provider route", "remote", c.remote, "provider", p.DeleteProviderRoute.ProviderUuid, "route", p.DeleteProviderRoute.RouteId)
		}
		return &pb.Response{Payload: &pb.Response_DeleteProviderRoute{DeleteProviderRoute: resp}}, nil
	case *pb.Request_ListProviderRoutes:
		resp := c.svc.listProviderRoutes(p.ListProviderRoutes.ProviderUuid)
		if resp.Error != "" {
			c.svc.log.Warn("failed to list provider routes", "remote", c.remote, "provider", p.ListProviderRoutes.ProviderUuid, "error", resp.Error)
		} else {
			c.svc.log.Debug("listed provider routes", "remote", c.remote, "provider", p.ListProviderRoutes.ProviderUuid)
		}
		return &pb.Response{Payload: &pb.Response_ListProviderRoutes{ListProviderRoutes: resp}}, nil
	case *pb.Request_AddProviderUser:
		resp := &pb.AddProviderUserResponse{}
		if err := c.svc.addProviderUser(p.AddProviderUser.ProviderUuid, p.AddProviderUser.User); err != nil {
			c.svc.log.Warn("failed to add provider user", "remote", c.remote, "provider", p.AddProviderUser.ProviderUuid, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("added provider user", "remote", c.remote, "provider", p.AddProviderUser.ProviderUuid, "user", p.AddProviderUser.User.GetUuid())
		}
		return &pb.Response{Payload: &pb.Response_AddProviderUser{AddProviderUser: resp}}, nil
	case *pb.Request_DeleteProviderUser:
		resp := &pb.DeleteProviderUserResponse{}
		if err := c.svc.deleteProviderUser(p.DeleteProviderUser.ProviderUuid, p.DeleteProviderUser.UserUuid); err != nil {
			c.svc.log.Warn("failed to delete provider user", "remote", c.remote, "provider", p.DeleteProviderUser.ProviderUuid, "user", p.DeleteProviderUser.UserUuid, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("deleted provider user", "remote", c.remote, "provider", p.DeleteProviderUser.ProviderUuid, "user", p.DeleteProviderUser.UserUuid)
		}
		return &pb.Response{Payload: &pb.Response_DeleteProviderUser{DeleteProviderUser: resp}}, nil
	case *pb.Request_ListProviderUsers:
		resp := c.svc.listProviderUsers(p.ListProviderUsers.ProviderUuid)
		if resp.Error != "" {
			c.svc.log.Warn("failed to list provider users", "remote", c.remote, "provider", p.ListProviderUsers.ProviderUuid, "error", resp.Error)
		} else {
			c.svc.log.Debug("listed provider users", "remote", c.remote, "provider", p.ListProviderUsers.ProviderUuid)
		}
		return &pb.Response{Payload: &pb.Response_ListProviderUsers{ListProviderUsers: resp}}, nil
	case *pb.Request_GetStats:
		resp := c.svc.getStats(p.GetStats)
		if resp.Error != "" {
			c.svc.log.Warn("failed to get stats", "remote", c.remote, "id", p.GetStats.InstanceId, "error", resp.Error)
		} else {
			c.svc.log.Debug("fetched stats", "remote", c.remote, "id", p.GetStats.InstanceId, "collect", p.GetStats.Collect)
		}
		return &pb.Response{Payload: &pb.Response_GetStats{GetStats: resp}}, nil
	case *pb.Request_ListSessions:
		resp := c.svc.listSessions(p.ListSessions.InstanceId)
		if resp.Error != "" {
			c.svc.log.Warn("failed to list sessions", "remote", c.remote, "id", p.ListSessions.InstanceId, "error", resp.Error)
		} else {
			c.svc.log.Debug("listed sessions", "remote", c.remote, "id", p.ListSessions.InstanceId)
		}
		return &pb.Response{Payload: &pb.Response_ListSessions{ListSessions: resp}}, nil
	case *pb.Request_Kick:
		resp := c.svc.kick(p.Kick)
		if resp.Error != "" {
			c.svc.log.Warn("failed to kick", "remote", c.remote, "id", p.Kick.InstanceId, "error", resp.Error)
		} else {
			c.svc.log.Info("kicked", "remote", c.remote, "id", p.Kick.InstanceId, "user", p.Kick.UserUuid, "session", p.Kick.SessionId, "tunnels", resp.Kicked)
		}
		return &pb.Response{Payload: &pb.Response_Kick{Kick: resp}}, nil
	default:
		return nil, fmt.Errorf("unknown request type")
	}
}

// addProvider creates and registers a new managed provider with the specified UUID
func (s *Server) addProvider(id, name string, providerData string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		id = uuid.New().String()
	} else if err := validateID(id); err != nil {
		return "", fmt.Errorf("invalid provider uuid: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.providers[id]; exists {
		return "", fmt.Errorf("provider with UUID %q already exists", id)
	}

	var providerCfg map[string]any
	if err := json.Unmarshal([]byte(providerData), &providerCfg); err != nil {
		return "", fmt.Errorf("parse provider config: %w", err)
	}

	providerType, ok := providerCfg["type"].(string)
	if !ok {
		return "", errors.New("provider config must have a 'type' field")
	}

	handler, err := common.ProvidersHolder.GetAny(providerType)
	if err != nil {
		return "", fmt.Errorf("failed to get provider handler for type %q: %w", providerType, err)
	}

	prov, ok := handler.(providers.Provider)
	if !ok {
		return "", fmt.Errorf("provider handler does not implement providers.Provider interface")
	}

	if err = prov.Update([]byte(providerData)); err != nil {
		return "", fmt.Errorf("failed to configure provider: %w", err)
	}

	mp := &ManagedProvider{
		UUID:     id,
		Name:     resolveInstanceName(name),
		Provider: prov,
		Config:   providerData,
	}
	s.providers[id] = mp

	if s.persistDir != "" {
		s.saveProvider(mp)
	}

	s.log.Info("added provider", "uuid", id, "name", mp.Name, "type", providerType)
	return id, nil
}

// listProviders returns info for all registered providers with their usage status
func (s *Server) listProviders() []*pb.ProviderInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	infos := make([]*pb.ProviderInfo, 0, len(s.providers))
	for _, mp := range s.providers {
		inUse := false
		for _, inst := range s.instances {
			if inst.ProviderUUID == mp.UUID {
				inUse = true
				break
			}
		}
		infos = append(infos, &pb.ProviderInfo{
			Uuid:  mp.UUID,
			Name:  mp.Name,
			InUse: inUse,
		})
	}
	return infos
}

// getProvider returns the full details for a single provider with usage status
func (s *Server) getProvider(uuid string) *pb.GetProviderResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	mp, ok := s.providers[uuid]
	if !ok {
		return &pb.GetProviderResponse{Error: fmt.Sprintf("provider %q not found", uuid)}
	}

	inUse := false
	for _, inst := range s.instances {
		if inst.ProviderUUID == uuid {
			inUse = true
			break
		}
	}

	return &pb.GetProviderResponse{
		Provider: &pb.ProviderInfo{
			Uuid:   mp.UUID,
			Name:   mp.Name,
			Config: mp.CurrentConfig(),
			InUse:  inUse,
		},
	}
}

// deleteProvider removes a provider - fails if any instance is using it
func (s *Server) deleteProvider(uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.providers[uuid]; !ok {
		return fmt.Errorf("provider %q not found", uuid)
	}

	for _, inst := range s.instances {
		if inst.ProviderUUID == uuid {
			return fmt.Errorf("cannot delete provider %q: instance %q is using it", uuid, inst.ID)
		}
	}

	mp := s.providers[uuid]
	delete(s.providers, uuid)

	if s.persistDir != "" {
		s.deletePersistedProvider(uuid)
	}

	if err := mp.Provider.Stop(); err != nil {
		s.log.Warn("failed to stop provider during deletion", "uuid", uuid, "error", err)
	}

	s.log.Info("deleted provider", "uuid", uuid, "name", mp.Name)
	return nil
}

// addProviderRoute adds a route to a provider
func (s *Server) addProviderRoute(providerUUID string, route *pb.RouteInfo) error {
	s.mu.RLock()
	mp, ok := s.providers[providerUUID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("provider %q not found", providerUUID)
	}
	if route == nil {
		return errors.New("route is required")
	}

	r := &providers.Route{
		ID:         route.Id,
		Address:    route.Address,
		Port:       int(route.Port),
		Socket:     route.Socket,
		Transport:  route.Transport,
		Encryption: route.Encryption,
		Name:       route.Name,
	}

	if err := r.Validate(); err != nil {
		return err
	}

	if err := mp.Provider.AddRoute(r); err != nil {
		return err
	}

	s.persistProvider(mp)
	return nil
}

// deleteProviderRoute removes a route from a provider
func (s *Server) deleteProviderRoute(providerUUID string, routeID string) error {
	s.mu.RLock()
	mp, ok := s.providers[providerUUID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("provider %q not found", providerUUID)
	}

	if err := mp.Provider.DeleteRoute(routeID); err != nil {
		return err
	}

	s.persistProvider(mp)
	return nil
}

// listProviderRoutes returns all routes from a provider
func (s *Server) listProviderRoutes(providerUUID string) *pb.ListProviderRoutesResponse {
	s.mu.RLock()
	mp, ok := s.providers[providerUUID]
	s.mu.RUnlock()
	if !ok {
		return &pb.ListProviderRoutesResponse{Error: fmt.Sprintf("provider %q not found", providerUUID)}
	}

	routes := mp.Provider.GetAllRoutes()
	pbRoutes := make([]*pb.RouteInfo, 0, len(routes))
	for _, r := range routes {
		pbRoutes = append(pbRoutes, &pb.RouteInfo{
			Id:         r.ID,
			Address:    r.Address,
			Port:       int32(r.Port),
			Socket:     r.Socket,
			Transport:  r.Transport,
			Encryption: r.Encryption,
			Name:       r.Name,
		})
	}

	return &pb.ListProviderRoutesResponse{Routes: pbRoutes}
}

// addProviderUser adds a user to a provider
func (s *Server) addProviderUser(providerUUID string, user *pb.UserInfo) error {
	s.mu.RLock()
	mp, ok := s.providers[providerUUID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("provider %q not found", providerUUID)
	}
	if user == nil {
		return errors.New("user is required")
	}

	u := &providers.User{
		UUID:          user.Uuid,
		AllowedRoutes: user.AllowedRoutes,
		Type:          user.Type,
		ForceTurn:     user.Forceturn,
		Peers:         int(user.Peers),
	}

	if err := mp.Provider.AddUser(u); err != nil {
		return err
	}

	s.persistProvider(mp)
	return nil
}

// deleteProviderUser removes a user from a provider
func (s *Server) deleteProviderUser(providerUUID string, userUUID string) error {
	s.mu.RLock()
	mp, ok := s.providers[providerUUID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("provider %q not found", providerUUID)
	}

	if err := mp.Provider.DeleteUser(userUUID); err != nil {
		return err
	}

	s.persistProvider(mp)
	s.kickProviderUser(providerUUID, userUUID)
	return nil
}

// listProviderUsers returns all users from a provider
func (s *Server) listProviderUsers(providerUUID string) *pb.ListProviderUsersResponse {
	s.mu.RLock()
	mp, ok := s.providers[providerUUID]
	s.mu.RUnlock()
	if !ok {
		return &pb.ListProviderUsersResponse{Error: fmt.Sprintf("provider %q not found", providerUUID)}
	}

	users := mp.Provider.GetAllUsers()
	pbUsers := make([]*pb.UserInfo, 0, len(users))
	for _, u := range users {
		pbUsers = append(pbUsers, &pb.UserInfo{
			Uuid:          u.UUID,
			AllowedRoutes: u.AllowedRoutes,
			Type:          u.Type,
			Forceturn:     u.ForceTurn,
			Peers:         int32(u.Peers),
		})
	}

	return &pb.ListProviderUsersResponse{Users: pbUsers}
}

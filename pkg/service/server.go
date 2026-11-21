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
	"github.com/theairblow/turnable/pkg/engine"
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

	opMu sync.Mutex // serializes instance lifecycle changes

	cfg     config.ServiceConfig // service config
	keyPair *KeyPair             // service key pair
	keys    keyring              // client public keys allowed to connect

	persistDir string // directory for persisted state

	listenersMu sync.Mutex     // guards listeners
	listeners   []net.Listener // open control listeners

	connsMu sync.Mutex               // guards conns
	conns   map[*clientConn]struct{} // open client connections

	throttle *throttle // blocks hosts that keep failing the handshake

	stopCh chan struct{}  // closed when the service stops
	bgWG   sync.WaitGroup // background goroutines
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

// usageDir is the persist subdirectory holding usage not yet collected by a panel
const usageDir = "usage"

const (
	maxConnections    = 256              // service client connections accepted at once
	usageSaveInterval = 30 * time.Second // how often uncollected usage is written to disk
	retryMinDelay     = 2 * time.Second  // first delay before restarting a failed autostart instance
	retryMaxDelay     = 60 * time.Second // upper bound of the restart delay
	persistDirMode    = 0o700            // persist directory permissions
	persistFileMode   = 0o600            // persisted file permissions, records can hold keys and tokens
)

// persistUsageRecord is the on-disk representation of uncollected usage
type persistUsageRecord struct {
	Token uint64                  `json:"token"` // Token of the latest collected batch
	Usage map[string]engine.Usage `json:"usage"` // Usage by user UUID
}

// writeFileAtomic replaces a file so readers never see a partial write
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), persistDirMode); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}

	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(persistFileMode); err != nil {
		_ = tmp.Close()
		return err
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}

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
	Stopped      bool     `json:"stopped,omitempty"`       // Stopped by an operator, stays stopped on boot
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

	if (len(cfg.AllowedKeys) > 0 || len(cfg.ReadonlyKeys) > 0) && kp == nil {
		return nil, errors.New("allowed client keys require a server keypair")
	}

	var keys keyring
	for _, group := range []struct {
		name string
		src  []string
		dst  *[][]byte
	}{
		{"allowed", cfg.AllowedKeys, &keys.admin},
		{"readonly", cfg.ReadonlyKeys, &keys.readonly},
	} {
		for _, k := range group.src {
			b, err := base64.StdEncoding.DecodeString(k)
			if err != nil {
				return nil, fmt.Errorf("decode %s client key: %w", group.name, err)
			}
			*group.dst = append(*group.dst, b)
		}
	}

	relay := newLogRelayHandler(slog.Default().Handler())
	common.SetLogHandler(relay)

	return &Server{
		instances:  make(map[string]*Instance),
		providers:  make(map[string]*ManagedProvider),
		log:        slog.Default(),
		relay:      relay,
		keyPair:    kp,
		keys:       keys,
		cfg:        *cfg,
		persistDir: cfg.PersistDir,
		conns:      make(map[*clientConn]struct{}),
		throttle:   newThrottle(),
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

	switch {
	case s.keyPair == nil:
		s.log.Warn("service runs without authentication, anyone who can reach its listeners has full control")
	case s.keys.open():
		s.log.Warn("service has no allowed_keys, any client with a keypair can connect")
	}

	s.stopCh = make(chan struct{})

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

		s.bgWG.Add(1)
		go s.usageLoop(s.stopCh)
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

// Stop closes all listeners and client connections and stops all managed instances
func (s *Server) Stop() error {
	if !s.running.CompareAndSwap(true, false) {
		return errors.New("not running")
	}

	close(s.stopCh)

	s.listenersMu.Lock()
	for _, ln := range s.listeners {
		_ = ln.Close()
	}

	s.listeners = nil
	s.listenersMu.Unlock()

	s.connsMu.Lock()
	for c := range s.conns {
		_ = c.raw.Close()
	}
	s.connsMu.Unlock()

	s.bgWG.Wait()

	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	instances, provs := s.instances, s.providers
	s.instances = make(map[string]*Instance)
	s.providers = make(map[string]*ManagedProvider)
	s.mu.Unlock()

	for _, inst := range instances {
		_ = inst.Stop()
		if s.persistDir != "" && inst.server != nil {
			s.saveUsage(inst)
		}
	}
	for _, mp := range provs {
		_ = mp.Provider.Stop()
	}

	return nil
}

// trackConn registers a connection unless the service is stopping or full
func (s *Server) trackConn(c *clientConn) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	if !s.running.Load() || len(s.conns) >= maxConnections {
		return false
	}

	s.conns[c] = struct{}{}
	return true
}

// untrackConn forgets a closed connection
func (s *Server) untrackConn(c *clientConn) {
	s.connsMu.Lock()
	delete(s.conns, c)
	s.connsMu.Unlock()
}

// accept accepts incoming connections from a listener and serves each one
func (s *Server) accept(ln net.Listener) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return
		}

		if s.throttle.blocked(hostOf(nc.RemoteAddr())) {
			s.log.Debug("rejected connection from a blocked host", "remote", nc.RemoteAddr())
			_ = nc.Close()
			continue
		}

		c := newClientConn(s, nc)
		if !s.trackConn(c) {
			s.log.Warn("rejected service connection", "remote", nc.RemoteAddr())
			_ = nc.Close()
			continue
		}

		go func() {
			defer s.untrackConn(c)
			c.serve()
		}()
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

// buildInstance creates the engine of an instance without starting it
func (s *Server) buildInstance(sp instanceSpec) (*Instance, error) {
	inst := &Instance{
		ID:          sp.id,
		name:        sp.name,
		autostart:   sp.autostart,
		config:      sp.config,
		listenAddrs: sp.listenAddrs,
	}

	if !sp.server {
		cli, err := buildClientInstance(sp.config)
		if err != nil {
			return nil, err
		}

		cli.SetLogger(s.log.With("client_id", sp.id))
		inst.client = cli
		return inst, nil
	}

	s.mu.RLock()
	mp, ok := s.providers[sp.providerUUID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("provider with UUID %q not found", sp.providerUUID)
	}

	srv, err := buildServerInstance(sp.config, mp.Provider)
	if err != nil {
		return nil, err
	}

	srv.SetLogger(s.log.With("server_id", sp.id))
	inst.server = srv
	inst.ProviderUUID = sp.providerUUID
	inst.provider = mp.Provider
	return inst, nil
}

// startServer creates and starts a Turnable server instance
func (s *Server) startServer(req *pb.StartServerRequest, providerUUID string) (string, error) {
	id, err := resolveInstanceID(req.InstanceId)
	if err != nil {
		return "", err
	}

	inst, err := s.buildInstance(instanceSpec{
		id:           id,
		name:         resolveInstanceName(req.Name),
		config:       req.Config,
		autostart:    req.Autostart,
		providerUUID: providerUUID,
		server:       true,
	})
	if err != nil {
		return "", err
	}

	if s.persistDir != "" {
		s.loadUsage(inst)
	}

	return id, s.addInstance(inst, true)
}

// startClient creates and starts a Turnable client instance
func (s *Server) startClient(req *pb.StartClientRequest) (string, error) {
	id, err := resolveInstanceID(req.InstanceId)
	if err != nil {
		return "", err
	}

	inst, err := s.buildInstance(instanceSpec{
		id:          id,
		name:        resolveInstanceName(req.Name),
		config:      req.Config,
		autostart:   req.Autostart,
		listenAddrs: req.ListenAddrs,
	})
	if err != nil {
		return "", err
	}

	return id, s.addInstance(inst, true)
}

// addInstance registers and persists an instance, then starts it asynchronously unless start is false
func (s *Server) addInstance(inst *Instance, start bool) error {
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

	if !start {
		_ = inst.Stop()
		inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STOPPED)
	}

	if s.persistDir != "" {
		if err := s.savePersisted(inst); err != nil {
			s.mu.Lock()
			delete(s.instances, inst.ID)
			s.mu.Unlock()
			_ = inst.Stop()
			return fmt.Errorf("persist instance: %w", err)
		}
	}

	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_CREATED)
	if !start {
		return nil
	}

	inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STARTING)
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
		inst.attempt.Store(0)
		go s.forwardSessionEvents(inst)
		s.setInstanceStatus(inst, pb.InstanceStatus_INSTANCE_STATUS_STARTED, pb.InstanceEventType_INSTANCE_EVENT_TYPE_STARTED)
		return
	}

	// Clients count as started only while the tunnel is actually connected
	for ev := range inst.client.Events() {
		if ev.Connected {
			inst.attempt.Store(0)
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

// failInstance marks a live instance as failed, broadcasts the event and schedules a retry for autostart instances
func (s *Server) failInstance(inst *Instance) {
	if inst.Stopped() {
		return
	}

	inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_FAILED)
	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_FAILED)

	if _, autostart := inst.meta(); !autostart {
		return
	}

	attempt := inst.attempt.Load()
	delay := min(retryMinDelay<<min(attempt, 5), retryMaxDelay)
	s.log.Info("instance will be restarted", "id", inst.ID, "in", delay.String())
	time.AfterFunc(delay, func() { s.retryInstance(inst, attempt+1) })
}

// retryInstance restarts a failed instance unless it was stopped or replaced in the meantime
func (s *Server) retryInstance(inst *Instance, attempt int32) {
	err := s.replaceInstance(inst.ID, inst, attempt, nil, false)
	if err != nil && !errors.Is(err, errInstanceReplaced) && !errors.Is(err, errNotRunning) {
		s.log.Warn("instance restart failed", "id", inst.ID, "error", err)
		inst.attempt.Store(attempt)
		s.failInstance(inst)
	}
}

var (
	errInstanceReplaced = errors.New("instance was replaced")
	errNotRunning       = errors.New("service is not running")
)

// replaceInstance swaps an instance for a freshly built one with the same ID and starts it, unless the old one was stopped and revive is not set.
// expect, when set, must still be the registered instance, mutate may change the spec the replacement is built from.
func (s *Server) replaceInstance(id string, expect *Instance, attempt int32, mutate func(*instanceSpec), revive bool) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	if !s.running.Load() {
		return errNotRunning
	}

	s.mu.RLock()
	old, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok && expect != nil {
		return errInstanceReplaced
	}
	if !ok {
		return fmt.Errorf("instance %q not found", id)
	}
	if expect != nil && (old != expect || old.Stopped()) {
		return errInstanceReplaced
	}

	wasStopped := old.GetStatus() == pb.InstanceStatus_INSTANCE_STATUS_STOPPED && !revive
	sp := old.spec()
	if mutate != nil {
		mutate(&sp)
	}

	inst, err := s.buildInstance(sp)
	if err != nil {
		return err
	}

	// Stop the old engine first so its listeners and ports are free again
	_ = old.Stop()
	if old.server != nil {
		inst.seedUsage(old.usageSnapshot())
	}

	inst.attempt.Store(attempt)

	s.mu.Lock()
	s.instances[id] = inst
	s.mu.Unlock()

	if wasStopped {
		_ = inst.Stop()
		inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STOPPED)
	} else {
		inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STARTING)
	}

	var persistErr error
	if s.persistDir != "" {
		persistErr = s.savePersisted(inst)
	}

	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_UPDATED)
	if !wasStopped {
		go s.runInstance(inst)
	}

	if persistErr != nil {
		return fmt.Errorf("applied but failed to persist: %w", persistErr)
	}
	return nil
}

// restartInstance restarts an instance from its stored config, also reviving a stopped one
func (s *Server) restartInstance(id string) error {
	return s.replaceInstance(id, nil, 0, nil, true)
}

// updateInstance applies an UpdateInstanceRequest
func (s *Server) updateInstance(req *pb.UpdateInstanceRequest) error {
	s.mu.RLock()
	inst, ok := s.instances[req.InstanceId]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("instance %q not found", req.InstanceId)
	}

	if len(req.ListenAddrs) > 0 && inst.server != nil {
		return errors.New("listen addresses can only be set on client instances")
	}

	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		return errors.New("name cannot be empty")
	}

	mutate := func(sp *instanceSpec) {
		if req.Name != nil {
			sp.name = resolveInstanceName(*req.Name)
		}
		if req.Autostart != nil {
			sp.autostart = *req.Autostart
		}
		if req.Config != nil {
			sp.config = *req.Config
		}
		if len(req.ListenAddrs) > 0 {
			sp.listenAddrs = req.ListenAddrs
		}
	}

	if req.Config != nil || len(req.ListenAddrs) > 0 {
		return s.replaceInstance(req.InstanceId, inst, inst.attempt.Load(), mutate, false)
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	sp := inst.spec()
	mutate(&sp)
	inst.setMeta(sp.name, sp.autostart)

	var persistErr error
	if s.persistDir != "" {
		persistErr = s.savePersisted(inst)
	}

	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_UPDATED)
	if persistErr != nil {
		return fmt.Errorf("applied but failed to persist: %w", persistErr)
	}
	return nil
}

// emitEvent broadcasts an InstanceEvent of the given type for an instance
func (s *Server) emitEvent(inst *Instance, event pb.InstanceEventType) {
	name, _ := inst.meta()
	s.broadcastEvent(&pb.InstanceEvent{
		InstanceId:   inst.ID,
		Name:         name,
		InstanceType: inst.Type(),
		EventType:    event,
	})
}

// stopInstance stops an instance and removes it, or only stops it and keeps it listed when keep is set
func (s *Server) stopInstance(id string, keep bool) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	inst, ok := s.instances[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("instance %q not found", id)
	}

	if !keep {
		delete(s.instances, id)
	}
	s.mu.Unlock()

	err := inst.Stop()
	inst.SetStatus(pb.InstanceStatus_INSTANCE_STATUS_STOPPED)

	if s.persistDir != "" {
		switch {
		case !keep:
			s.deletePersisted(id)
		default:
			if perr := s.savePersisted(inst); perr != nil {
				err = errors.Join(err, fmt.Errorf("persist instance: %w", perr))
			}
		}

		if inst.server != nil {
			if keep {
				s.saveUsage(inst)
			} else {
				s.deleteUsage(id)
			}
		}
	}

	s.emitEvent(inst, pb.InstanceEventType_INSTANCE_EVENT_TYPE_STOPPED)
	return err
}

// broadcastEvent sends an InstanceEvent to all connected service clients
func (s *Server) broadcastEvent(event *pb.InstanceEvent) {
	for _, c := range s.relay.broadcast.snapshot() {
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
func (s *Server) savePersisted(inst *Instance) error {
	name, autostart := inst.meta()
	rec := persistRecord{
		ID:           inst.ID,
		Name:         name,
		Autostart:    autostart,
		Config:       inst.config,
		ListenAddrs:  inst.listenAddrs,
		ProviderUUID: inst.ProviderUUID,
		Type:         "client",
		Stopped:      inst.GetStatus() == pb.InstanceStatus_INSTANCE_STATUS_STOPPED,
	}
	if inst.server != nil {
		rec.Type = "server"
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	return writeFileAtomic(filepath.Join(s.persistDir, inst.ID+".json"), data)
}

// deletePersisted removes a persisted instance record from disk
func (s *Server) deletePersisted(id string) {
	path := filepath.Join(s.persistDir, id+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		s.log.Warn("persist: failed to remove record", "path", path, "error", err)
	}
}

// saveUsage writes the usage of a server instance that no panel has confirmed yet
func (s *Server) saveUsage(inst *Instance) {
	usage, token := inst.usageSnapshot()
	if len(usage) == 0 {
		s.deleteUsage(inst.ID)
		return
	}

	data, err := json.Marshal(persistUsageRecord{Token: token, Usage: usage})
	if err != nil {
		s.log.Warn("persist: failed to marshal usage", "id", inst.ID, "error", err)
		return
	}

	if err := writeFileAtomic(filepath.Join(s.persistDir, usageDir, inst.ID+".json"), data); err != nil {
		s.log.Warn("persist: failed to write usage", "id", inst.ID, "error", err)
	}
}

// loadUsage restores the unconfirmed usage of a server instance saved by an earlier run
func (s *Server) loadUsage(inst *Instance) {
	path := filepath.Join(s.persistDir, usageDir, inst.ID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Warn("persist: failed to read usage", "path", path, "error", err)
		}
		return
	}

	var rec persistUsageRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		s.log.Warn("persist: failed to parse usage", "path", path, "error", err)
		return
	}

	inst.seedUsage(rec.Usage, rec.Token)
}

// deleteUsage removes the persisted usage of an instance
func (s *Server) deleteUsage(id string) {
	path := filepath.Join(s.persistDir, usageDir, id+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		s.log.Warn("persist: failed to remove usage", "path", path, "error", err)
	}
}

// usageLoop periodically saves the usage of running server instances until the service stops
func (s *Server) usageLoop(stop <-chan struct{}) {
	defer s.bgWG.Done()

	ticker := time.NewTicker(usageSaveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.mu.RLock()
			servers := make([]*Instance, 0, len(s.instances))
			for _, inst := range s.instances {
				if inst.server != nil {
					servers = append(servers, inst)
				}
			}
			s.mu.RUnlock()

			for _, inst := range servers {
				s.saveUsage(inst)
			}
		}
	}
}

// persistProvider saves a provider record if persistence is enabled
func (s *Server) persistProvider(mp *ManagedProvider) error {
	if s.persistDir == "" {
		return nil
	}

	if err := s.saveProvider(mp); err != nil {
		return fmt.Errorf("applied but failed to persist: %w", err)
	}
	return nil
}

// saveProvider writes a provider record with its current config to the persist directory
func (s *Server) saveProvider(mp *ManagedProvider) error {
	data, err := json.MarshalIndent(persistProviderRecord{
		UUID:   mp.UUID,
		Name:   mp.Name,
		Config: json.RawMessage(mp.CurrentConfig()),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal provider record: %w", err)
	}

	return writeFileAtomic(filepath.Join(s.persistDir, providersDir, mp.UUID+".json"), data)
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

		if rec.Type != "server" && rec.Type != "client" {
			s.log.Warn("persist: unknown instance type in record", "path", path, "type", rec.Type)
			continue
		}

		switch {
		case !rec.Autostart || rec.Stopped:
			err = s.loadStopped(rec)
		case rec.Type == "server":
			_, err = s.startServer(&pb.StartServerRequest{
				Config:       rec.Config,
				InstanceId:   rec.ID,
				Name:         rec.Name,
				Autostart:    rec.Autostart,
				ProviderUuid: rec.ProviderUUID,
			}, rec.ProviderUUID)
		default:
			_, err = s.startClient(&pb.StartClientRequest{
				Config:      rec.Config,
				ListenAddrs: rec.ListenAddrs,
				InstanceId:  rec.ID,
				Name:        rec.Name,
				Autostart:   rec.Autostart,
			})
		}

		if err != nil {
			s.log.Warn("persist: failed to restore instance", "id", rec.ID, "error", err)
		} else {
			s.log.Info("persist: restored instance", "id", rec.ID, "name", rec.Name, "type", rec.Type)
		}
	}
}

// loadStopped registers a persisted instance in the stopped state so it can be restarted later
func (s *Server) loadStopped(rec persistRecord) error {
	id, err := resolveInstanceID(rec.ID)
	if err != nil {
		return err
	}

	inst, err := s.buildInstance(instanceSpec{
		id:           id,
		name:         resolveInstanceName(rec.Name),
		config:       rec.Config,
		autostart:    rec.Autostart,
		providerUUID: rec.ProviderUUID,
		listenAddrs:  rec.ListenAddrs,
		server:       rec.Type == "server",
	})
	if err != nil {
		return err
	}

	if inst.server != nil {
		s.loadUsage(inst)
	}

	return s.addInstance(inst, false)
}

// clientConn handles a single service client connection
type clientConn struct {
	svc     *Server           // owning service
	raw     net.Conn          // connection as accepted, used to force it closed
	nc      net.Conn          // client connection, encrypted after the handshake
	remote  net.Addr          // client address
	role    role              // access level of the client
	writeCh chan *pb.Response // responses waiting to be written
	closing chan struct{}     // closed when the read side ends, the writer flushes and exits
	done    chan struct{}     // closed when the writer exits
}

// newClientConn allocates a clientConn for an incoming connection
func newClientConn(svc *Server, nc net.Conn) *clientConn {
	return &clientConn{
		svc:     svc,
		raw:     nc,
		nc:      nc,
		remote:  nc.RemoteAddr(),
		writeCh: make(chan *pb.Response, 256),
		closing: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// serve performs the handshake, subscribes to logs, then runs the IO loops
func (c *clientConn) serve() {
	defer c.nc.Close()

	c.svc.log.Debug("client initiating handshake", "remote", c.remote)

	wrapped, pubKey, role, err := serverHandshake(c.nc, c.svc.keyPair, &c.svc.keys)
	if err != nil {
		c.svc.log.Warn("service handshake failed", "remote", c.remote, "error", err)
		c.svc.throttle.fail(hostOf(c.remote))
		return
	}
	c.nc = wrapped
	c.role = role
	c.svc.throttle.succeed(hostOf(c.remote))

	fingerprint := keyFingerprint(pubKey)
	c.svc.log.Info("client connected", "remote", c.remote, "key", fingerprint, "readonly", role == roleReadOnly)
	c.svc.relay.broadcast.subscribe(c)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		c.writeLoop()
	}()

	c.readLoop()

	c.svc.relay.broadcast.unsubscribe(c)
	close(c.closing)
	<-writerDone
	c.svc.log.Info("client disconnected", "remote", c.remote, "key", fingerprint)
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

		if resp != nil {
			resp.RequestId = req.RequestId
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

// writeLoop sends queued responses to the client until the connection ends, then flushes what is left
func (c *clientConn) writeLoop() {
	defer c.nc.Close()
	defer close(c.done)

	write := func(resp *pb.Response) bool {
		return writeFramed(c.nc, resp) == nil && resp.GetError() == nil
	}

	for {
		select {
		case resp := <-c.writeCh:
			if !write(resp) {
				return
			}
		case <-c.closing:
			for {
				select {
				case resp := <-c.writeCh:
					if !write(resp) {
						return
					}
				default:
					return
				}
			}
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
		c.svc.log.Warn("disconnecting slow client", "remote", c.remote, "id", event.InstanceId)
		_ = c.raw.Close()
	}
}

// dispatch handles an incoming request and sends a response
func (c *clientConn) dispatch(req *pb.Request) (*pb.Response, error) {
	if !c.svc.running.Load() {
		return nil, errors.New("service is stopping")
	}

	if c.role == roleReadOnly && !isReadOnlyRequest(req) {
		c.svc.log.Warn("read-only client attempted a change", "remote", c.remote)
		return nil, errors.New("permission denied: this key is read-only")
	}

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
		if err := c.svc.stopInstance(p.StopInstance.InstanceId, p.StopInstance.Keep); err != nil {
			c.svc.log.Warn("failed to stop instance", "remote", c.remote, "id", p.StopInstance.InstanceId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("stopped instance", "remote", c.remote, "id", p.StopInstance.InstanceId)
		}

		return &pb.Response{Payload: &pb.Response_StopInstance{StopInstance: resp}}, nil
	case *pb.Request_RestartInstance:
		resp := &pb.RestartInstanceResponse{}
		if err := c.svc.restartInstance(p.RestartInstance.InstanceId); err != nil {
			c.svc.log.Warn("failed to restart instance", "remote", c.remote, "id", p.RestartInstance.InstanceId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("restarted instance", "remote", c.remote, "id", p.RestartInstance.InstanceId)
		}

		return &pb.Response{Payload: &pb.Response_RestartInstance{RestartInstance: resp}}, nil
	case *pb.Request_UpdateInstance:
		resp := &pb.UpdateInstanceResponse{}
		if err := c.svc.updateInstance(p.UpdateInstance); err != nil {
			c.svc.log.Warn("failed to update instance", "remote", c.remote, "id", p.UpdateInstance.InstanceId, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("updated instance", "remote", c.remote, "id", p.UpdateInstance.InstanceId)
		}

		return &pb.Response{Payload: &pb.Response_UpdateInstance{UpdateInstance: resp}}, nil
	case *pb.Request_UpdateProvider:
		resp := &pb.UpdateProviderResponse{}
		if err := c.svc.updateProvider(p.UpdateProvider); err != nil {
			c.svc.log.Warn("failed to update provider", "remote", c.remote, "uuid", p.UpdateProvider.Uuid, "error", err)
			resp.Error = err.Error()
		} else {
			c.svc.log.Info("updated provider", "remote", c.remote, "uuid", p.UpdateProvider.Uuid)
		}

		return &pb.Response{Payload: &pb.Response_UpdateProvider{UpdateProvider: resp}}, nil
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

	prov, err := newProvider(providerData)
	if err != nil {
		return "", err
	}

	mp := &ManagedProvider{
		UUID:     id,
		Name:     resolveInstanceName(name),
		Provider: prov,
		Config:   providerData,
	}
	s.providers[id] = mp

	if s.persistDir != "" {
		if err := s.saveProvider(mp); err != nil {
			delete(s.providers, id)
			_ = prov.Stop()
			return "", fmt.Errorf("persist provider: %w", err)
		}
	}

	s.log.Info("added provider", "uuid", id, "name", mp.Name, "type", prov.ID())
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

// updateProvider renames a provider or reloads it with a new config
func (s *Server) updateProvider(req *pb.UpdateProviderRequest) error {
	s.mu.RLock()
	mp, ok := s.providers[req.Uuid]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("provider %q not found", req.Uuid)
	}

	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		return errors.New("name cannot be empty")
	}

	if req.Config != nil {
		check, err := newProvider(*req.Config)
		if err != nil {
			return err
		}

		_ = check.Stop()
		if check.ID() != mp.Provider.ID() {
			return fmt.Errorf("provider type cannot change from %q to %q", mp.Provider.ID(), check.ID())
		}

		if err := mp.Provider.Update([]byte(*req.Config)); err != nil {
			return fmt.Errorf("failed to reload provider: %w", err)
		}
	}

	s.mu.Lock()
	if req.Name != nil {
		mp.Name = strings.TrimSpace(*req.Name)
	}
	if req.Config != nil {
		mp.Config = *req.Config
	}
	s.mu.Unlock()

	return s.persistProvider(mp)
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

	return s.persistProvider(mp)
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

	return s.persistProvider(mp)
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

	return s.persistProvider(mp)
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

	s.kickProviderUser(providerUUID, userUUID)
	return s.persistProvider(mp)
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

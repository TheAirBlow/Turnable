package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/engine"
	pb "github.com/theairblow/turnable/pkg/service/proto"
)

// Instance represents a managed Turnable server or client instance
type Instance struct {
	ID           string                 // Unique instance ID
	ProviderUUID string                 // UUID of the provider this instance uses (servers only)
	metaMu       sync.RWMutex           // Guards name and autostart
	name         string                 // Display name
	autostart    bool                   // Auto-start on service boot, also retries failed starts
	config       string                 // Raw config JSON
	listenAddrs  []string               // Listen addresses (clients only)
	server       *engine.TurnableServer // Server instance (nil for clients)
	client       *engine.TurnableClient // Client instance (nil for servers)
	status       atomic.Int32           // Current status
	provider     providers.Provider     // Provider instance (servers only)
	lifeMu       sync.Mutex             // Serializes start and stop
	stopped      bool                   // Whether Stop was called
	unsubscribe  func()                 // Stops the session event feed (servers only)
	attempt      atomic.Int32           // Failed starts in a row, drives the retry backoff

	usageMu sync.Mutex              // Guards unacked and token
	unacked map[string]engine.Usage // Collected usage the panel has not confirmed yet (servers only)
	token   uint64                  // Token of the latest collected batch
}

// instanceSpec holds everything needed to build an instance
type instanceSpec struct {
	id           string   // Instance ID
	name         string   // Display name
	config       string   // Raw config
	autostart    bool     // Start with the service
	providerUUID string   // Provider UUID, servers only
	listenAddrs  []string // Listen addresses, clients only
	server       bool     // Whether this is a server instance
}

// meta returns the display name and autostart flag
func (i *Instance) meta() (string, bool) {
	i.metaMu.RLock()
	defer i.metaMu.RUnlock()
	return i.name, i.autostart
}

// setMeta changes the display name and autostart flag
func (i *Instance) setMeta(name string, autostart bool) {
	i.metaMu.Lock()
	defer i.metaMu.Unlock()
	i.name, i.autostart = name, autostart
}

// spec returns the parameters this instance was built from
func (i *Instance) spec() instanceSpec {
	name, autostart := i.meta()
	return instanceSpec{
		id:           i.ID,
		name:         name,
		config:       i.config,
		autostart:    autostart,
		providerUUID: i.ProviderUUID,
		listenAddrs:  i.listenAddrs,
		server:       i.server != nil,
	}
}

// collectUsage collects the usage since the last collect and returns every batch not yet acknowledged with its token.
// A nil ack is a client that does not confirm, it gets everything pending once and nothing is kept.
func (i *Instance) collectUsage(ack *uint64) (map[string]engine.Usage, uint64) {
	i.usageMu.Lock()
	defer i.usageMu.Unlock()

	if ack != nil && *ack == i.token {
		i.unacked = nil
	}

	pending := i.unacked
	if pending == nil {
		pending = map[string]engine.Usage{}
	}

	for uuid, d := range i.server.CollectUsage() {
		cur := pending[uuid]
		pending[uuid] = engine.Usage{Up: cur.Up + d.Up, Down: cur.Down + d.Down}
	}

	i.token++
	if ack == nil {
		i.unacked = nil
		return pending, i.token
	}

	i.unacked = pending
	out := make(map[string]engine.Usage, len(pending))
	for uuid, d := range pending {
		out[uuid] = d
	}
	return out, i.token
}

// usageSnapshot returns all usage nobody has confirmed yet without touching the counters
func (i *Instance) usageSnapshot() (map[string]engine.Usage, uint64) {
	i.usageMu.Lock()
	defer i.usageMu.Unlock()

	out := make(map[string]engine.Usage, len(i.unacked))
	for uuid, d := range i.unacked {
		out[uuid] = d
	}

	for uuid, d := range i.server.PendingUsage() {
		cur := out[uuid]
		out[uuid] = engine.Usage{Up: cur.Up + d.Up, Down: cur.Down + d.Down}
	}

	return out, i.token
}

// seedUsage restores unconfirmed usage carried over from an earlier run of this instance
func (i *Instance) seedUsage(usage map[string]engine.Usage, token uint64) {
	i.usageMu.Lock()
	defer i.usageMu.Unlock()
	i.unacked = usage
	i.token = token
}

// errInstanceStopped is returned when an instance is started after being stopped
var errInstanceStopped = errors.New("instance was stopped")

// Start starts the underlying server or client unless the instance was already stopped
func (i *Instance) Start() error {
	i.lifeMu.Lock()
	defer i.lifeMu.Unlock()

	if i.stopped {
		return errInstanceStopped
	}

	if i.server != nil {
		return i.server.Start()
	}

	return i.client.Start(i.listenAddrs)
}

// Stopped returns whether the instance was stopped
func (i *Instance) Stopped() bool {
	i.lifeMu.Lock()
	defer i.lifeMu.Unlock()
	return i.stopped
}

// Type returns the protobuf type of this instance
func (i *Instance) Type() pb.InstanceType {
	if i.server != nil {
		return pb.InstanceType_INSTANCE_TYPE_SERVER
	}
	return pb.InstanceType_INSTANCE_TYPE_CLIENT
}

// Stop stops the instance
func (i *Instance) Stop() error {
	i.lifeMu.Lock()
	defer i.lifeMu.Unlock()

	if i.stopped {
		return nil
	}
	i.stopped = true

	if i.unsubscribe != nil {
		i.unsubscribe()
	}

	if i.server != nil && i.server.IsRunning() {
		return i.server.Stop()
	}

	if i.client != nil && i.client.IsRunning() {
		return i.client.Stop()
	}

	return nil
}

// Info returns a protobuf description of this instance
func (i *Instance) Info() *pb.InstanceInfo {
	name, autostart := i.meta()
	info := &pb.InstanceInfo{
		Id:        i.ID,
		Name:      name,
		Status:    pb.InstanceStatus(i.status.Load()),
		Autostart: autostart,
		Type:      i.Type(),
	}

	return info
}

// SetStatus sets the instance status atomically
func (i *Instance) SetStatus(status pb.InstanceStatus) {
	i.status.Store(int32(status))
}

// GetStatus returns the current instance status
func (i *Instance) GetStatus() pb.InstanceStatus {
	return pb.InstanceStatus(i.status.Load())
}

// buildServerInstance returns a TurnableServer from a server config and provider
func buildServerInstance(rawConfig string, provider providers.Provider) (*engine.TurnableServer, error) {
	cfg, err := config.ParseServerConfig([]byte(rawConfig))
	if err != nil {
		return nil, fmt.Errorf("parse server config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate server config: %w", err)
	}

	return engine.NewTurnableServer(cfg, provider), nil
}

// buildClientInstance returns a TurnableClient from a client config
func buildClientInstance(rawConfig string) (*engine.TurnableClient, error) {
	cfg, err := config.ParseClientConfig([]byte(rawConfig))
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate client config: %w", err)
	}

	return engine.NewTurnableClient(cfg), nil
}

// handleValidateServerConfig validates a server config
func handleValidateServerConfig(req *pb.ValidateServerConfigRequest) *pb.ValidateServerConfigResponse {
	cfg, err := config.ParseServerConfig([]byte(req.Config))
	if err != nil {
		return &pb.ValidateServerConfigResponse{Error: err.Error()}
	}

	if err := cfg.Validate(); err != nil {
		return &pb.ValidateServerConfigResponse{Error: err.Error()}
	}

	return &pb.ValidateServerConfigResponse{Valid: true}
}

// handleValidateClientConfig validates a client config JSON or URL
func handleValidateClientConfig(req *pb.ValidateClientConfigRequest) *pb.ValidateClientConfigResponse {
	cfg, err := config.ParseClientConfig([]byte(req.Config))
	if err != nil {
		return &pb.ValidateClientConfigResponse{Error: err.Error()}
	}

	if err := cfg.Validate(); err != nil {
		return &pb.ValidateClientConfigResponse{Error: err.Error()}
	}

	return &pb.ValidateClientConfigResponse{Valid: true}
}

// handleConvertClientConfig converts a client config between JSON and URL form
func handleConvertClientConfig(req *pb.ConvertClientConfigRequest) (*pb.ConvertClientConfigResponse, error) {
	cfg, err := config.ParseClientConfig([]byte(req.Config))
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if strings.HasPrefix(strings.TrimSpace(req.Config), "turnable://") {
		out, err := cfg.ToJSON(false, false)
		if err != nil {
			return nil, fmt.Errorf("convert to json: %w", err)
		}

		return &pb.ConvertClientConfigResponse{Config: string(out)}, nil
	}

	out, err := cfg.ToURL()
	if err != nil {
		return nil, fmt.Errorf("convert to url: %w", err)
	}
	return &pb.ConvertClientConfigResponse{Config: out}, nil
}

// newProvider creates a provider from its config JSON and initializes it
func newProvider(rawConfig string) (providers.Provider, error) {
	var providerCfg map[string]any
	if err := json.Unmarshal([]byte(rawConfig), &providerCfg); err != nil {
		return nil, fmt.Errorf("parse provider config: %w", err)
	}

	providerType, ok := providerCfg["type"].(string)
	if !ok {
		return nil, errors.New("provider config must have a 'type' field")
	}

	handler, err := common.ProvidersHolder.GetAny(providerType)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider handler for type %q: %w", providerType, err)
	}

	prov, ok := handler.(providers.Provider)
	if !ok {
		return nil, errors.New("provider handler does not implement providers.Provider interface")
	}

	if err := prov.Update([]byte(rawConfig)); err != nil {
		return nil, fmt.Errorf("failed to configure provider: %w", err)
	}

	return prov, nil
}

// handleValidateProviderConfig validates a provider config by loading it into a throwaway provider
func handleValidateProviderConfig(req *pb.ValidateProviderConfigRequest) *pb.ValidateProviderConfigResponse {
	prov, err := newProvider(req.Config)
	if err != nil {
		return &pb.ValidateProviderConfigResponse{Error: err.Error()}
	}

	_ = prov.Stop()
	return &pb.ValidateProviderConfigResponse{Valid: true}
}

// setUnsubscribe stores the function that ends the session event feed, calling it right away if the instance already stopped
func (i *Instance) setUnsubscribe(fn func()) {
	i.lifeMu.Lock()
	defer i.lifeMu.Unlock()

	if i.stopped {
		fn()
		return
	}

	i.unsubscribe = fn
}

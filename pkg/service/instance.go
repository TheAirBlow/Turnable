package service

import (
	"encoding/json"
	"fmt"
	"strings"
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
	Name         string                 // Display name
	Autostart    bool                   // Auto-start on service boot
	ProviderUUID string                 // UUID of the provider this instance uses (servers only)
	config       string                 // Raw config JSON
	listenAddrs  []string               // Listen addresses (clients only)
	server       *engine.TurnableServer // Server instance (nil for clients)
	client       *engine.TurnableClient // Client instance (nil for servers)
	status       atomic.Int32           // Current status
	provider     providers.Provider     // Provider instance (servers only)
}

// Stop stops the instance
func (i *Instance) Stop() error {
	if i.server != nil {
		return i.server.Stop()
	}

	if i.client != nil {
		return i.client.Stop()
	}

	return nil
}

// Info returns a protobuf description of this instance
func (i *Instance) Info() *pb.InstanceInfo {
	info := &pb.InstanceInfo{
		Id:        i.ID,
		Name:      i.Name,
		Status:    pb.InstanceStatus(i.status.Load()),
		Autostart: i.Autostart,
	}

	if i.server != nil {
		info.Type = pb.InstanceType_INSTANCE_TYPE_SERVER
	} else {
		info.Type = pb.InstanceType_INSTANCE_TYPE_CLIENT
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

// buildServerInstance returns a TurnableServer from a StartServerRequest and provider
func buildServerInstance(req *pb.StartServerRequest, provider providers.Provider) (*engine.TurnableServer, error) {
	cfg, err := config.ParseServerConfig([]byte(req.Config))
	if err != nil {
		return nil, fmt.Errorf("parse server config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate server config: %w", err)
	}

	return engine.NewTurnableServer(cfg, provider), nil
}

// buildClientInstance returns a TurnableClient from a StartClientRequest
func buildClientInstance(req *pb.StartClientRequest) (*engine.TurnableClient, error) {
	cfg, err := config.ParseClientConfig([]byte(req.Config))
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

// handleValidateProviderConfig validates a provider config
func handleValidateProviderConfig(req *pb.ValidateProviderConfigRequest) *pb.ValidateProviderConfigResponse {
	var providerCfg map[string]any
	if err := json.Unmarshal([]byte(req.Config), &providerCfg); err != nil {
		return &pb.ValidateProviderConfigResponse{Error: fmt.Sprintf("parse config: %v", err)}
	}

	providerType, ok := providerCfg["type"].(string)
	if !ok {
		return &pb.ValidateProviderConfigResponse{Error: "provider config must have a 'type' field"}
	}

	_, err := common.ProvidersHolder.GetAny(providerType)
	if err != nil {
		return &pb.ValidateProviderConfigResponse{Error: fmt.Sprintf("invalid provider type: %v", err)}
	}

	// TODO: providers dont have any validation routines just yet

	return &pb.ValidateProviderConfigResponse{Valid: true}
}

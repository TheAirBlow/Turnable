package service

import (
	"fmt"
	"strings"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/engine"
	pb "github.com/theairblow/turnable/pkg/service/proto"
	"github.com/theairblow/turnable/pkg/tunnels"
)

// Instance represents a managed Turnable server or client
type Instance struct {
	ID       string
	server   *engine.TurnableServer
	client   *engine.TurnableClient
	provider config.Provider
}

// Stop stops the instance
func (i *Instance) Stop() error {
	if i.server != nil {
		return i.server.Stop()
	}

	return i.client.Stop()
}

// Info returns a protobuf description of this instance
func (i *Instance) Info() *pb.InstanceInfo {
	info := &pb.InstanceInfo{Id: i.ID}
	if i.server != nil {
		info.Type = pb.InstanceType_INSTANCE_TYPE_SERVER
		info.Running = i.server.IsRunning()
	} else {
		info.Type = pb.InstanceType_INSTANCE_TYPE_CLIENT
		info.Running = i.client.IsRunning()
	}

	return info
}

// buildTunnelHandler constructs a tunnel handler from a protobuf config
func buildTunnelHandler(cfg *pb.TunnelHandlerConfig) (tunnels.Handler, error) {
	if cfg == nil {
		return &tunnels.SocketHandler{}, nil
	}

	switch cfg.Id {
	case "socket", "":
		h := &tunnels.SocketHandler{}
		if v := cfg.Args["local_addr"]; v != nil {
			if sv, ok := v.Value.(*pb.ParamValue_StringVal); ok {
				h.LocalAddr = sv.StringVal
			}
		}
		return h, nil
	default:
		return nil, fmt.Errorf("unknown tunnel handler: %s", cfg.Id)
	}
}

// buildProviderConfig constructs a config provider from a ProviderConfig proto message
func buildProviderConfig(cfg *pb.ProviderConfig) (config.Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("provider config is required")
	}

	switch cfg.Id {
	case "json":
		var data string
		if v := cfg.Args["data"]; v != nil {
			if sv, ok := v.Value.(*pb.ParamValue_StringVal); ok {
				data = sv.StringVal
			}
		}

		p, err := providers.NewJSONProviderFromJSON(data)
		if err != nil {
			return nil, fmt.Errorf("create json provider: %w", err)
		}

		return p, nil
	default:
		return nil, fmt.Errorf("unknown provider type %q", cfg.Id)
	}
}

// buildServerInstance returns a TurnableServer and its provider from a StartServerRequest
func buildServerInstance(req *pb.StartServerRequest) (*engine.TurnableServer, config.Provider, error) {
	provider, err := buildProviderConfig(req.Provider)
	if err != nil {
		return nil, nil, err
	}

	cfg, err := config.NewServerConfigFromJSON(req.Config, provider)
	if err != nil {
		return nil, nil, fmt.Errorf("parse server config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("validate server config: %w", err)
	}

	return engine.NewTurnableServer(*cfg), provider, nil
}

// buildClientInstance returns a TurnableClient from a StartClientRequest
func buildClientInstance(req *pb.StartClientRequest) (*engine.TurnableClient, error) {
	cfg, err := parseClientConfig(req.Config)
	if err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate client config: %w", err)
	}

	return engine.NewTurnableClient(*cfg), nil
}

// parseClientConfig auto-detects JSON vs URL and parses accordingly
func parseClientConfig(raw string) (*config.ClientConfig, error) {
	if strings.HasPrefix(strings.TrimSpace(raw), "turnable://") {
		return config.NewClientConfigFromURL(raw)
	}

	return config.NewClientConfigFromJSON(raw)
}

// handleValidateServerConfig validates a server config against a provider config
func handleValidateServerConfig(req *pb.ValidateServerConfigRequest) *pb.ValidateServerConfigResponse {
	provider, err := buildProviderConfig(req.Provider)
	if err != nil {
		return &pb.ValidateServerConfigResponse{Error: err.Error()}
	}

	cfg, err := config.NewServerConfigFromJSON(req.Config, provider)
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
	cfg, err := parseClientConfig(req.Config)
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
	cfg, err := parseClientConfig(req.Config)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if strings.HasPrefix(strings.TrimSpace(req.Config), "turnable://") {
		out, err := cfg.ToJSON(false)
		if err != nil {
			return nil, fmt.Errorf("convert to json: %w", err)
		}

		return &pb.ConvertClientConfigResponse{Config: out}, nil
	}

	return &pb.ConvertClientConfigResponse{Config: cfg.ToURL()}, nil
}

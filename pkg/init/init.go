package init

import (
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/connection"
	"github.com/theairblow/turnable/pkg/connection/direct"
	"github.com/theairblow/turnable/pkg/connection/relay"
	"github.com/theairblow/turnable/pkg/platform"
	"github.com/theairblow/turnable/pkg/platform/vk"
	"github.com/theairblow/turnable/pkg/protocol"
	"github.com/theairblow/turnable/pkg/transport"
)

func init() {
	// Config Providers
	common.ProvidersHolder = providers.Providers
	providers.Providers.Register(&providers.RawProvider{})
	providers.Providers.Register(&providers.JSONProvider{})

	// Connection Handlers
	common.ConnectionsHolder = connection.Handlers
	connection.Handlers.Register(&relay.Handler{})
	connection.Handlers.Register(&direct.Handler{})

	// Platform Handlers
	common.PlatformsHolder = platform.Handlers
	platform.Handlers.Register(&vk.Handler{})

	// Protocols
	common.ProtocolsHolder = protocol.Handlers
	protocol.Handlers.Register(&protocol.DTLSHandler{})
	protocol.Handlers.Register(&protocol.SRTPHandler{})
	protocol.Handlers.Register(&protocol.NoneHandler{})

	// Transports
	common.TransportsHolder = transport.Handlers
	transport.Handlers.Register(&transport.NoneHandler{})
	transport.Handlers.Register(&transport.SCTPHandler{})
	transport.Handlers.Register(&transport.KCPHandler{})
}

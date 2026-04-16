package connection

import (
	"context"
	"io"
	"net"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
)

// Handler represents a connection handler
type Handler interface {
	ID() string                                                   // Returns the unique ID of this handler
	Start(config config.ServerConfig) error                       // Starts the VPN server
	Stop() error                                                  // Stops the VPN server
	Connect(config config.ClientConfig, sessionUUID string) error // Connects to a VPN server
	OpenChannel(socketType string) (io.ReadWriteCloser, error)    // Opens a data channel for the given socket type ("tcp"/"udp")
	Disconnect() error                                            // Gracefully disconnects from the current VPN server
	Close() error                                                 // Forcibly closes the current VPN server connection
	AcceptNewClients(ctx context.Context) <-chan ServerClient     // Emits an event for every new client
}

// ServerClient represents a server client's Address and IO
type ServerClient struct {
	Address        net.Addr             // IP and port of the client
	IO             io.ReadWriteCloser   // Client IO stream
	Config         *config.ClientConfig // Authenticated client config
	User           *config.User         // Authenticated user
	Route          *config.Route        // Requested route
	SessionUUID    string               // Multi-peer session identifier
	CloseRequested <-chan struct{}      // closed when client sends CloseRequest (half-close)
}

// Handlers represents connection Handler registry
var Handlers = common.NewRegistry[Handler]()

// init registers all available connection handlers
func init() {
	common.ConnectionsHolder = Handlers
	Handlers.Register(&RelayHandler{})
}

// GetHandler fetches a connection Handler by its string ID
func GetHandler(name string) (Handler, error) {
	return Handlers.Get(name)
}

// ListHandlers lists all connection Handler string IDs
func ListHandlers() []string {
	return Handlers.List()
}

// HandlerExists checks whether a connection Handler with specified string ID exists
func HandlerExists(name string) bool {
	return Handlers.Exists(name)
}

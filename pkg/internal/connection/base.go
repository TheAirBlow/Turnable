package connection

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
)

// ErrReconnecting is returned when a full reconnect is in progress.
var ErrReconnecting = errors.New("full reconnect is in progress")

// Handler represents a connection handler
type Handler interface {
	ID() string                                                     // Returns the unique ID of this handler
	Start(config config.ServerConfig) error                         // Starts the server listener
	Stop() error                                                    // Stops the server listener
	AcceptClients(ctx context.Context) (<-chan ServerClient, error) // Accepts and emits new authenticated server clients
	Connect(config config.ClientConfig) error                       // Connects to a remote server
	OpenChannel(routeIdx byte) (net.Conn, error)                    // Opens a new logical data channel for the given route index
	Disconnect() error                                              // Gracefully disconnects from the current remote server
	Close() error                                                   // Forcibly closes the current remove server connection
	SetLogger(log *slog.Logger)                                     // Changes the slog logger instance
}

// ServerClient represents a server client
type ServerClient struct {
	Address     net.Addr             // IP and port of the client
	Conn        net.Conn             // Client connection
	Config      *config.ClientConfig // Authenticated client config
	User        *config.User         // Authenticated user
	Routes      []config.Route       // All routes authorized for this session
	RouteIdx    byte                 // Index into Routes selected for this channel
	SessionUUID string               // Multi-peer session identifier
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

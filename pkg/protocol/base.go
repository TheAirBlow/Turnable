package protocol

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/theairblow/turnable/pkg/common"
)

// ErrQuotaReached indicates a TURN allocation quota has been exhausted
var ErrQuotaReached = errors.New("turn allocation quota reached")

// ErrUnauthorized indicates a TURN authorization failure
var ErrUnauthorized = errors.New("turn server authorization failed")

// TURNInfo describes the TURN server used to establish the packet underlay
type TURNInfo struct {
	Address  string // TURN server address
	Username string // TURN username
	Password string // TURN password
}

// ServerClient represents an accepted client session
type ServerClient struct {
	Address net.Addr // Client address
	Conn    net.Conn // Client connection
}

// Handler represents a protocol handler
type Handler interface {
	ID() string                                                                                  // Returns the unique ID of this handler
	Start(listenAddr string) error                                                               // Starts the server listener
	Stop() error                                                                                 // Stops the server listener
	AcceptClients(ctx context.Context) (<-chan ServerClient, error)                              // Accepts new server clients
	Connect(ctx context.Context, dest net.Addr, turn TURNInfo, forceTURN bool) (net.Conn, error) // Connects to a remote server directly or via TURN
	SetLogger(log *slog.Logger)                                                                  // Changes the slog logger instance
}

// Handlers represents protocol Handler registry.
var Handlers = common.NewRegistry[Handler]()

// GetHandler fetches a protocol Handler by its string ID.
func GetHandler(name string) (Handler, error) {
	return Handlers.Get(name)
}

// ListHandlers lists all protocol Handler string IDs.
func ListHandlers() []string {
	return Handlers.List()
}

// HandlerExists checks whether a protocol Handler with specified string ID exists.
func HandlerExists(name string) bool {
	return Handlers.Exists(name)
}

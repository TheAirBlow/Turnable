package tunnels

import (
	"context"
	"io"
	"net"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
)

// AcceptedClient is a local client connection accepted from a tunnel
type AcceptedClient struct {
	// Stream is the bidirectional connection to the local client
	Stream io.ReadWriteCloser
	// Close is called to release any resources associated with the client
	Close func() error
}

// Handler provides local client acceptance and remote route dialing
type Handler interface {
	ID() string
	// Open starts accepting local clients for the given socket type and returns a stream channel
	Open(ctx context.Context, socketType string) (<-chan AcceptedClient, error)
	// Connect dials a remote endpoint described by the route and returns the connection
	Connect(ctx context.Context, route *config.Route) (net.Conn, error)
}

// Handlers represents tunnel handler registry.
var Handlers = common.NewRegistry[Handler]()

// init registers the default socket tunnel handler
func init() {
	Handlers.Register(&SocketHandler{})
}

// GetHandler fetches a tunnel handler by its string ID.
func GetHandler(name string) (Handler, error) {
	return Handlers.Get(name)
}

// ListHandlers lists all registered tunnel handler IDs.
func ListHandlers() []string {
	return Handlers.List()
}

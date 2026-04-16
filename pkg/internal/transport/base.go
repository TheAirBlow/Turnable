package transport

import (
	"io"

	"github.com/theairblow/turnable/pkg/common"
)

// Handler provides an optional stream transport layer for reliability
type Handler interface {
	ID() string
	WrapClient(stream io.ReadWriteCloser) (io.ReadWriteCloser, error)
	WrapServer(stream io.ReadWriteCloser) (io.ReadWriteCloser, error)
}

// Handlers represents transport handler registry.
var Handlers = common.NewRegistry[Handler]()

// init wires the transport registry and registers all built-in handlers.
func init() {
	common.TransportsHolder = Handlers
	Handlers.Register(&SCTPHandler{})
	Handlers.Register(&KCPHandler{})
}

// GetHandler fetches a transport handler by its string ID.
func GetHandler(name string) (Handler, error) {
	return Handlers.Get(name)
}

// ListHandlers lists all transport handler string IDs.
func ListHandlers() []string {
	return Handlers.List()
}

// HandlerExists checks whether a transport handler with specified string ID exists.
func HandlerExists(name string) bool {
	return Handlers.Exists(name)
}

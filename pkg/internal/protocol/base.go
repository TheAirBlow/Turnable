package protocol

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
)

// ErrQuotaReached indicates a TURN allocation quota has been exhausted.
var ErrQuotaReached = errors.New("turn allocation quota reached")

// RelayInfo describes the TURN server used to establish the packet underlay.
type RelayInfo struct {
	Address   string   // TURN server address
	Addresses []string // All available TURN server addresses
	Username  string   // TURN username
	Password  string   // TURN password
}

// ServerClient represents an accepted client session.
type ServerClient struct {
	Address net.Addr
	IO      io.ReadWriteCloser
}

// Handler manages protocol lifecycle and secure session establishment.
type Handler interface {
	ID() string
	Start(config config.ServerConfig) error
	Stop() error
	Connect(dest net.Addr, turn RelayInfo, forceTURN bool) (io.ReadWriteCloser, error)
	ConnectRaw(dest net.Addr, turn RelayInfo, forceTURN bool) (io.ReadWriteCloser, error)
	Disconnect() error
	Close() error
	AcceptNewClients(ctx context.Context) <-chan ServerClient
}

// Handlers represents protocol Handler registry.
var Handlers = common.NewRegistry[Handler]()

// init registers all available protocol handlers
func init() {
	common.ProtocolsHolder = Handlers
	Handlers.Register(&DTLSHandler{})
}

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

// ConnectRawLog calls ConnectRawWithLogger if the handler supports it, otherwise ConnectRaw
func ConnectRawLog(h Handler, dest net.Addr, relay RelayInfo, forceTURN bool, log *slog.Logger) (io.ReadWriteCloser, error) {
	type loggable interface {
		ConnectRawWithLogger(net.Addr, RelayInfo, bool, *slog.Logger) (io.ReadWriteCloser, error)
	}
	if lh, ok := h.(loggable); ok && log != nil {
		return lh.ConnectRawWithLogger(dest, relay, forceTURN, log)
	}
	return h.ConnectRaw(dest, relay, forceTURN)
}

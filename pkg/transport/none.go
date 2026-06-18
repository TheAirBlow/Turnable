package transport

import (
	"net"
)

// NoneHandler represents a passthrough transport handler
type NoneHandler struct{}

// ID returns the unique ID of this handler
func (D *NoneHandler) ID() string {
	return "none"
}

// WrapClient returns the connection as-is
func (D *NoneHandler) WrapClient(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

// WrapServer returns the connection as-is
func (D *NoneHandler) WrapServer(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

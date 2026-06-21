package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
)

// validateClientConfig parses the client config JSON, validates it and authorizes access to every requested route.
func (D *Handler) validateClientConfig(configJSON []byte) (ClientConfig, *providers.User, []providers.Route, error) {
	clientCfg, err := config.ParseConfigGeneric[ClientConfig](configJSON)
	if err != nil {
		return clientCfg, nil, nil, fmt.Errorf("failed to parse client config json: %w", err)
	}

	if common.IsNullOrWhiteSpace(clientCfg.UserUUID) {
		return clientCfg, nil, nil, errors.New("relay handshake missing user_uuid")
	}
	if len(clientCfg.Routes) == 0 {
		return clientCfg, nil, nil, errors.New("relay handshake missing routes")
	}
	if clientCfg.Type != "relay" {
		return clientCfg, nil, nil, fmt.Errorf("unexpected connection type %q", clientCfg.Type)
	}

	switch clientCfg.Encryption {
	case "handshake", "full":
	default:
		return clientCfg, nil, nil, fmt.Errorf("invalid relay encryption mode %q", clientCfg.Encryption)
	}

	user, err := D.provider.GetUser(clientCfg.UserUUID)
	if err != nil {
		return clientCfg, nil, nil, fmt.Errorf("failed to resolve user: %w", err)
	}

	routes := make([]providers.Route, 0, len(clientCfg.Routes))
	for i, cr := range clientCfg.Routes {
		route, err := D.provider.GetRoute(cr.RouteID)
		if err != nil {
			return clientCfg, nil, nil, fmt.Errorf("failed to resolve route %d (%q): %w", i, cr.RouteID, err)
		}

		isAllowed := false
		for _, routeID := range user.AllowedRoutes {
			if routeID == route.ID {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return clientCfg, nil, nil, fmt.Errorf("user %s is not authorized for route %s", user.UUID, route.ID)
		}
		if cr.Socket != route.Socket {
			return clientCfg, nil, nil, fmt.Errorf("route %d (%q): expected socket %s, got %s", i, cr.RouteID, route.Socket, cr.Socket)
		}
		routes = append(routes, *route)
	}

	return clientCfg, user, routes, nil
}

// writePrimaryHello sends a primary handshake hello packet
func writePrimaryHello(w io.Writer, challenge [8]byte, configJSON []byte) error {
	configBytes := configJSON
	buf := make([]byte, 0, 1+8+1+4+len(configBytes))
	buf = append(buf, relayHelloTypePrimary)
	buf = append(buf, challenge[:]...)
	buf = append(buf, relayHandshakeVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(configBytes)))
	buf = append(buf, configBytes...)
	_, err := w.Write(buf)
	return err
}

// parsePrimaryHello parses a primary handshake hello packet
func parsePrimaryHello(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, errors.New("primary hello too short")
	}
	if data[0] != relayHandshakeVersion {
		return nil, fmt.Errorf("unsupported primary hello version %d", data[0])
	}
	configLen := binary.BigEndian.Uint32(data[1:5])
	if configLen == 0 {
		return nil, errors.New("primary hello: empty config JSON")
	}
	if len(data) < 5+int(configLen) {
		return nil, errors.New("primary hello: truncated config")
	}
	return data[5 : 5+configLen], nil
}

// writeSecondaryHello sends a secondary handshake hello packet
func writeSecondaryHello(w io.Writer, challenge [8]byte, sessionUUID [16]byte, userUUID string) error {
	userBytes := []byte(userUUID)
	buf := make([]byte, 0, 1+8+1+16+2+len(userBytes))
	buf = append(buf, relayHelloTypeSecondary)
	buf = append(buf, challenge[:]...)
	buf = append(buf, relayHandshakeVersion)
	buf = append(buf, sessionUUID[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(userBytes)))
	buf = append(buf, userBytes...)
	_, err := w.Write(buf)
	return err
}

// parseSecondaryHello parses a secondary handshake hello packet
func parseSecondaryHello(data []byte) ([16]byte, string, error) {
	if len(data) < 19 { // version(1) + uuid(16) + userLen(2)
		return [16]byte{}, "", errors.New("secondary hello too short")
	}
	if data[0] != relayHandshakeVersion {
		return [16]byte{}, "", fmt.Errorf("unsupported secondary hello version %d", data[0])
	}
	var sessionUUID [16]byte
	copy(sessionUUID[:], data[1:17])
	userLen := binary.BigEndian.Uint16(data[17:19])
	off := 19
	if len(data) < off+int(userLen) {
		return [16]byte{}, "", errors.New("secondary hello: truncated user uuid")
	}
	userUUID := string(data[off : off+int(userLen)])
	return sessionUUID, userUUID, nil
}

// writePrimaryAck sends a primary handshake ack packet
func writePrimaryAck(w io.Writer, sessionUUID [16]byte, errMsg string) error {
	if errMsg == "" {
		buf := make([]byte, 0, 1+1+16)
		buf = append(buf, relayHandshakeVersion, relayAckOK)
		buf = append(buf, sessionUUID[:]...)
		_, err := w.Write(buf)
		return err
	}
	errBytes := []byte(errMsg)
	buf := make([]byte, 0, 1+1+2+len(errBytes))
	buf = append(buf, relayHandshakeVersion, relayAckErr)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(errBytes)))
	buf = append(buf, errBytes...)
	_, err := w.Write(buf)
	return err
}

// parsePrimaryAck parses a primary handshake ack packet
func parsePrimaryAck(data []byte) ([16]byte, string, error) {
	if len(data) < 2 {
		return [16]byte{}, "", errors.New("primary ack too short")
	}
	if data[0] != relayHandshakeVersion {
		return [16]byte{}, "", fmt.Errorf("unsupported primary ack version %d", data[0])
	}
	if data[1] == relayAckOK {
		if len(data) < 18 {
			return [16]byte{}, "", errors.New("primary ack uuid too short")
		}
		var sessionUUID [16]byte
		copy(sessionUUID[:], data[2:18])
		return sessionUUID, "", nil
	}
	if len(data) < 4 {
		return [16]byte{}, "", errors.New("primary ack error too short")
	}
	errLen := binary.BigEndian.Uint16(data[2:4])
	if len(data) < 4+int(errLen) {
		return [16]byte{}, "", errors.New("primary ack error truncated")
	}
	return [16]byte{}, string(data[4 : 4+errLen]), nil
}

// writeSecondaryAck sends a secondary handshake packet
func writeSecondaryAck(w io.Writer, errMsg string) error {
	if errMsg == "" {
		_, err := w.Write([]byte{relayHandshakeVersion, relayAckOK})
		return err
	}
	errBytes := []byte(errMsg)
	buf := make([]byte, 0, 1+1+2+len(errBytes))
	buf = append(buf, relayHandshakeVersion, relayAckErr)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(errBytes)))
	buf = append(buf, errBytes...)
	_, err := w.Write(buf)
	return err
}

// parseSecondaryAck parses a secondary handshake ack packet
func parseSecondaryAck(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("secondary ack too short")
	}
	if data[0] != relayHandshakeVersion {
		return "", fmt.Errorf("unsupported secondary ack version %d", data[0])
	}
	if data[1] == relayAckOK {
		return "", nil
	}
	if len(data) < 4 {
		return "", errors.New("secondary ack error too short")
	}
	errLen := binary.BigEndian.Uint16(data[2:4])
	if len(data) < 4+int(errLen) {
		return "", errors.New("secondary ack error truncated")
	}
	return string(data[4 : 4+errLen]), nil
}

// doClientPrimaryHandshake performs the full client primary handshake
func doClientPrimaryHandshake(conn net.Conn, configJSON []byte) ([16]byte, error) {
	var challenge [8]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return [16]byte{}, fmt.Errorf("read challenge: %w", err)
	}
	if err := writePrimaryHello(conn, challenge, configJSON); err != nil {
		return [16]byte{}, fmt.Errorf("write primary hello: %w", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return [16]byte{}, fmt.Errorf("read primary ack: %w", err)
	}
	sessionUUID, errMsg, err := parsePrimaryAck(buf[:n])
	if err != nil {
		return [16]byte{}, err
	}
	if errMsg != "" {
		return [16]byte{}, &ErrAckRejected{msg: errMsg}
	}
	return sessionUUID, nil
}

// doClientSecondaryHandshake performs the full client secondary handshake
func doClientSecondaryHandshake(conn net.Conn, sessionUUID [16]byte, userUUID string) error {
	var challenge [8]byte
	if _, err := io.ReadFull(conn, challenge[:]); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	if err := writeSecondaryHello(conn, challenge, sessionUUID, userUUID); err != nil {
		return fmt.Errorf("write secondary hello: %w", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read secondary ack: %w", err)
	}
	errMsg, err := parseSecondaryAck(buf[:n])
	if err != nil {
		return err
	}
	if errMsg != "" {
		return &ErrAckRejected{msg: errMsg}
	}
	return nil
}

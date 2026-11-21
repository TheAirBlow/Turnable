package service

import (
	"bytes"
	"crypto/mlkem"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	pb "github.com/theairblow/turnable/pkg/service/proto"
	"google.golang.org/protobuf/proto"
)

const (
	serviceVersion = uint32(3) // Server protocol version

	maxFrameSize       = 8 * 1024 * 1024 // Largest accepted frame after the handshake
	maxHandshakeFrame  = 16 * 1024       // Largest accepted frame during the handshake
	handshakeTimeout   = 10 * time.Second
	handshakeConfirmed = "TSVC-OK" // First encrypted frame each side sends to prove it derived the same keys
)

// role is the access level of a service client
type role int

const (
	roleAdmin    role = iota // full control
	roleReadOnly             // read-only requests
)

// keyring holds the client public keys the service accepts
type keyring struct {
	admin    [][]byte // keys with full access
	readonly [][]byte // keys with read-only access
}

// open reports whether any client key is accepted
func (k *keyring) open() bool {
	return len(k.admin) == 0 && len(k.readonly) == 0
}

// lookup returns the role of a client public key
func (k *keyring) lookup(pub []byte) (role, bool) {
	if k.open() {
		return roleAdmin, true
	}

	for _, a := range k.admin {
		if bytes.Equal(a, pub) {
			return roleAdmin, true
		}
	}

	for _, r := range k.readonly {
		if bytes.Equal(r, pub) {
			return roleReadOnly, true
		}
	}

	return 0, false
}

// writeFramed writes a length-prefixed proto message without encryption
func writeFramed(nc net.Conn, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	frame := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	frame = append(frame, data...)

	_, err = nc.Write(frame)
	return err
}

// readFramed reads a length-prefixed proto message without decryption
func readFramed(nc net.Conn, msg proto.Message) error {
	return readFramedLimit(nc, msg, maxFrameSize)
}

// readFramedLimit reads a length-prefixed proto message of at most limit bytes
func readFramedLimit(nc net.Conn, msg proto.Message, limit uint32) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(nc, lenBuf[:]); err != nil {
		return err
	}

	size := binary.BigEndian.Uint32(lenBuf[:])
	if size > limit {
		return fmt.Errorf("message too large: %d bytes", size)
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(nc, data); err != nil {
		return err
	}

	return proto.Unmarshal(data, msg)
}

// confirmKeys exchanges the first encrypted frame, which only succeeds when both sides derived the same keys
func confirmKeys(ec net.Conn, send bool) error {
	if send {
		_, err := ec.Write([]byte(handshakeConfirmed))
		return err
	}

	buf := make([]byte, len(handshakeConfirmed)+1)
	n, err := ec.Read(buf)
	if err != nil {
		return err
	}

	if string(buf[:n]) != handshakeConfirmed {
		return errors.New("key confirmation mismatch")
	}

	return nil
}

// joinSecrets builds the session secret from both encapsulated secrets
func joinSecrets(clientSide, serverSide []byte) []byte {
	return append(append([]byte{}, clientSide...), serverSide...)
}

// serverHandshake sends ServerHello and negotiates encryption, returns wrapped conn, client public key and its role.
// The client proves it holds the private key of the public key it claims, since only that key can decapsulate the second secret.
func serverHandshake(nc net.Conn, kp *KeyPair, keys *keyring) (net.Conn, []byte, role, error) {
	_ = nc.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = nc.SetDeadline(time.Time{}) }()

	hello := &pb.ServerHello{
		Magic:        "TSVC",
		Version:      serviceVersion,
		AuthRequired: kp != nil,
	}
	if kp != nil {
		hello.PublicKey = kp.pubKeyBytes
	}

	if err := writeFramed(nc, hello); err != nil {
		return nil, nil, 0, fmt.Errorf("write server hello: %w", err)
	}
	if kp == nil {
		return nc, nil, roleAdmin, nil
	}

	var clientHello pb.ClientHello
	if err := readFramedLimit(nc, &clientHello, maxHandshakeFrame); err != nil {
		return nil, nil, 0, fmt.Errorf("read client hello: %w", err)
	}

	clientRole, ok := keys.lookup(clientHello.PublicKey)
	if !ok {
		return nil, nil, 0, errors.New("client public key not in allowlist")
	}

	clientKey, err := mlkem.NewEncapsulationKey768(clientHello.PublicKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("invalid client public key: %w", err)
	}

	clientSecret, err := kp.privKey.Decapsulate(clientHello.Ciphertext)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("decapsulate: %w", err)
	}

	serverSecret, challenge := clientKey.Encapsulate()
	if err := writeFramed(nc, &pb.ServerAuth{Ciphertext: challenge}); err != nil {
		return nil, nil, 0, fmt.Errorf("write server auth: %w", err)
	}

	wrapped := newEncryptedConn(nc, newServiceEncLayer(joinSecrets(clientSecret, serverSecret), false))

	// The peer is unproven until its confirmation decrypts, so keep its frame small
	wrapped.maxSize = maxHandshakeFrame
	if err := confirmKeys(wrapped, false); err != nil {
		return nil, nil, 0, fmt.Errorf("client key proof: %w", err)
	}
	wrapped.maxSize = maxFrameSize

	if err := confirmKeys(wrapped, true); err != nil {
		return nil, nil, 0, fmt.Errorf("write key confirmation: %w", err)
	}

	return wrapped, clientHello.PublicKey, clientRole, nil
}

// clientHandshake reads ServerHello and negotiates encryption, returns wrapped conn.
// A pinned server key makes the handshake fail when the server presents another key or no encryption at all.
func clientHandshake(nc net.Conn, kp *KeyPair, serverPub []byte) (net.Conn, error) {
	_ = nc.SetDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = nc.SetDeadline(time.Time{}) }()

	var serverHello pb.ServerHello
	if err := readFramedLimit(nc, &serverHello, maxHandshakeFrame); err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}

	if serverHello.Magic != "TSVC" {
		return nil, fmt.Errorf("invalid magic: %s", serverHello.Magic)
	}

	if serverHello.Version != serviceVersion {
		return nil, fmt.Errorf("unsupported version: %d", serverHello.Version)
	}

	if !serverHello.AuthRequired {
		if len(serverPub) > 0 {
			return nil, errors.New("server does not use encryption but a server key is pinned")
		}
		return nc, nil
	}

	if kp == nil {
		return nil, fmt.Errorf("server requires auth but no client keypair provided")
	}

	if len(serverPub) > 0 && !bytes.Equal(serverPub, serverHello.PublicKey) {
		return nil, errors.New("server public key does not match the pinned key")
	}

	// Encapsulate shared secret using server public key
	encKey, err := mlkem.NewEncapsulationKey768(serverHello.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	clientSecret, ciphertext := encKey.Encapsulate()

	clientHello := &pb.ClientHello{
		Ciphertext: ciphertext,
		PublicKey:  kp.pubKeyBytes,
	}

	if err := writeFramed(nc, clientHello); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}

	var auth pb.ServerAuth
	if err := readFramedLimit(nc, &auth, maxHandshakeFrame); err != nil {
		return nil, fmt.Errorf("read server auth (is the client key allowed?): %w", err)
	}

	serverSecret, err := kp.privKey.Decapsulate(auth.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulate server auth: %w", err)
	}

	wrapped := newEncryptedConn(nc, newServiceEncLayer(joinSecrets(clientSecret, serverSecret), true))
	if err := confirmKeys(wrapped, true); err != nil {
		return nil, fmt.Errorf("write key confirmation: %w", err)
	}

	if err := confirmKeys(wrapped, false); err != nil {
		return nil, fmt.Errorf("server key proof: %w", err)
	}

	return wrapped, nil
}

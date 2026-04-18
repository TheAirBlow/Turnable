package connection

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	encryptedTunnelMagic   = "TENC"
	encryptedTunnelVersion = 1
)

// EncryptedConn wraps a net.Conn with per-packet AES-256-GCM-12 encryption
type EncryptedConn struct {
	conn net.Conn

	readAEAD  cipher.AEAD
	writeAEAD cipher.AEAD

	readPrefix  [4]byte
	writePrefix [4]byte
	writeSeq    uint64

	readMu  sync.Mutex
	writeMu sync.Mutex
}

// wrapClientEncryptedConn bootstraps the encrypted tunnel from the client side
func wrapClientEncryptedConn(conn net.Conn, serverPubKey string) (*EncryptedConn, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server public key: %w", err)
	}

	pubKey, err := mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	sharedKey, ciphertext := pubKey.Encapsulate()
	if err := writeClientHello(conn, ciphertext); err != nil {
		return nil, err
	}

	return newEncryptedConn(conn, sharedKey, true)
}

// wrapServerEncryptedConn bootstraps the encrypted tunnel from the server side
func wrapServerEncryptedConn(conn net.Conn, serverPrivKey string) (*EncryptedConn, error) {
	privBytes, err := base64.StdEncoding.DecodeString(serverPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server private key: %w", err)
	}

	privKey, err := mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server private key: %w", err)
	}

	ciphertext, err := readClientHello(conn)
	if err != nil {
		return nil, err
	}

	sharedKey, err := privKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate client tunnel key: %w", err)
	}

	return newEncryptedConn(conn, sharedKey, false)
}

// newEncryptedConn derives directional AEAD contexts from one shared key
func newEncryptedConn(conn net.Conn, sharedKey []byte, isClient bool) (*EncryptedConn, error) {
	clientWriteKey, clientWritePrefix := deriveTunnelMaterial(sharedKey, "client->server")
	serverWriteKey, serverWritePrefix := deriveTunnelMaterial(sharedKey, "server->client")

	var readKey, writeKey []byte
	var readPrefix, writePrefix [4]byte
	if isClient {
		writeKey, writePrefix = clientWriteKey, clientWritePrefix
		readKey, readPrefix = serverWriteKey, serverWritePrefix
	} else {
		writeKey, writePrefix = serverWriteKey, serverWritePrefix
		readKey, readPrefix = clientWriteKey, clientWritePrefix
	}

	readAEAD, err := newTunnelAEAD(readKey)
	if err != nil {
		return nil, err
	}
	writeAEAD, err := newTunnelAEAD(writeKey)
	if err != nil {
		return nil, err
	}

	return &EncryptedConn{
		conn:        conn,
		readAEAD:    readAEAD,
		writeAEAD:   writeAEAD,
		readPrefix:  readPrefix,
		writePrefix: writePrefix,
	}, nil
}

// deriveTunnelMaterial splits the shared key into per-direction key and nonce material
func deriveTunnelMaterial(sharedKey []byte, label string) ([]byte, [4]byte) {
	keyHash := sha256.Sum256(append(append([]byte{}, sharedKey...), []byte(" key "+label)...))
	prefixHash := sha256.Sum256(append(append([]byte{}, sharedKey...), []byte(" nonce "+label)...))
	var prefix [4]byte
	copy(prefix[:], prefixHash[:4])
	return keyHash[:], prefix
}

// newTunnelAEAD creates a new AEAD tunnel used for encryption
func newTunnelAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aes cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithTagSize(block, 12)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aes-gcm: %w", err)
	}
	return aead, nil
}

// writeClientHello sends the client hello packet
func writeClientHello(conn net.Conn, ciphertext []byte) error {
	header := make([]byte, 0, 4+1+2+len(ciphertext))
	header = append(header, encryptedTunnelMagic...)
	header = append(header, encryptedTunnelVersion)
	header = binary.BigEndian.AppendUint16(header, uint16(len(ciphertext)))
	header = append(header, ciphertext...)

	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("failed to write encrypted tunnel hello: %w", err)
	}

	return nil
}

// readClientHello reads the client hello packet
func readClientHello(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted tunnel hello: %w", err)
	}
	buf = buf[:n]

	if n < 7 {
		return nil, fmt.Errorf("encrypted tunnel hello too short: %d bytes", n)
	}

	magic := []byte(encryptedTunnelMagic)
	if !bytes.Equal(buf[:4], magic) {
		return nil, fmt.Errorf("invalid encrypted tunnel magic: got=%q hex=%s", string(buf[:4]), hex.EncodeToString(buf[:7]))
	}
	if buf[4] != encryptedTunnelVersion {
		return nil, fmt.Errorf("unsupported encrypted tunnel version %d", buf[4])
	}

	cipherLen := binary.BigEndian.Uint16(buf[5:7])
	if cipherLen == 0 {
		return nil, errors.New("encrypted tunnel ciphertext is empty")
	}

	if n < 7+int(cipherLen) {
		return nil, fmt.Errorf("encrypted tunnel hello truncated: need %d, got %d", 7+cipherLen, n)
	}

	return buf[7 : 7+cipherLen], nil
}

// Read decrypts one incoming datagram
func (t *EncryptedConn) Read(p []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	tmp := make([]byte, len(p)+20)
	n, err := t.conn.Read(tmp)
	if err != nil {
		return 0, err
	}

	if n < 8+t.readAEAD.Overhead() {
		return 0, errors.New("encrypted packet too short")
	}

	var nonce [12]byte
	copy(nonce[:4], t.readPrefix[:])
	copy(nonce[4:], tmp[:8])

	plain, err := t.readAEAD.Open(nil, nonce[:], tmp[8:n], nil)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt packet: %w", err)
	}

	if len(plain) > len(p) {
		return 0, fmt.Errorf("decrypted packet too large for buffer: %d > %d", len(plain), len(p))
	}

	copy(p, plain)
	return len(plain), nil
}

// Write encrypts buffer and sends it as one datagram
func (t *EncryptedConn) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	var nonce [12]byte
	copy(nonce[:4], t.writePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:], t.writeSeq)
	t.writeSeq++

	ciphertext := t.writeAEAD.Seal(nil, nonce[:], p, nil)
	out := make([]byte, 0, 8+len(ciphertext))
	out = append(out, nonce[4:]...)
	out = append(out, ciphertext...)

	if _, err := t.conn.Write(out); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Underlying returns the raw conn beneath the encryption layer
func (t *EncryptedConn) Underlying() net.Conn {
	return t.conn
}

// Close closes the underlying connection
func (t *EncryptedConn) Close() error {
	return t.conn.Close()
}

// LocalAddr returns the local network address
func (t *EncryptedConn) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr returns the remote network address
func (t *EncryptedConn) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

// SetDeadline sets the deadline on the underlying connection
func (t *EncryptedConn) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

// SetReadDeadline sets the read deadline on the underlying connection
func (t *EncryptedConn) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline sets the write deadline on the underlying connection
func (t *EncryptedConn) SetWriteDeadline(deadline time.Time) error {
	return t.conn.SetWriteDeadline(deadline)
}

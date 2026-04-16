package connection

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/theairblow/turnable/pkg/common"
)

const (
	encryptedTunnelMagic   = "MXE1"
	encryptedTunnelVersion = 1
	maxTunnelPlainChunk    = 16 * 1024
)

// EncryptedTunnel wraps a stream with frame-level AES-GCM encryption.
type EncryptedTunnel struct {
	stream io.ReadWriteCloser

	readAEAD  cipher.AEAD
	writeAEAD cipher.AEAD

	readPrefix  [4]byte
	writePrefix [4]byte

	readBuf []byte

	readMu  sync.Mutex
	writeMu sync.Mutex
}

// EncryptedPacketConn wraps a net.PacketConn with stateless AEAD encryption suitable for UDP.
type EncryptedPacketConn struct {
	pc net.PacketConn

	readAEAD  cipher.AEAD
	writeAEAD cipher.AEAD

	readPrefix  [4]byte
	writePrefix [4]byte

	readMu  sync.Mutex
	writeMu sync.Mutex
}

// wrapClientEncryptedStream bootstraps the encrypted tunnel from the client side.
func wrapClientEncryptedStream(stream io.ReadWriteCloser, serverPubKey string) (*EncryptedTunnel, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server public key: %w", err)
	}

	pubKey, err := mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	// DTLS delivers data as whole records; small-buffer reads (ReadFullRetry)
	// would receive errBufferTooSmall (a Temporary error), causing ReadFullRetry
	// to retry after the record has already been consumed - deadlocking until the
	// deadline fires. A bufio.Reader absorbs the full DTLS record and re-exposes
	// it as a byte stream so sequential small reads work correctly.
	buffered := common.WrapBufferedReadStream(stream, 4096)

	sharedKey, ciphertext := pubKey.Encapsulate()
	if err := writeTunnelClientHello(buffered, ciphertext); err != nil {
		return nil, err
	}

	return newEncryptedTunnel(buffered, sharedKey, true)
}

// wrapServerEncryptedStream bootstraps the encrypted tunnel from the server side.
func wrapServerEncryptedStream(stream io.ReadWriteCloser, serverPrivKey string) (*EncryptedTunnel, error) {
	privBytes, err := base64.StdEncoding.DecodeString(serverPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server private key: %w", err)
	}

	privKey, err := mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server private key: %w", err)
	}

	// Same DTLS record-boundary issue as on the client side: wrap with a
	// buffered reader so that ReadFullRetry on the 7-byte hello header works
	// even though the full 1095-byte ML-KEM record arrives in one shot.
	buffered := common.WrapBufferedReadStream(stream, 4096)

	ciphertext, err := readTunnelClientHello(buffered)
	if err != nil {
		return nil, err
	}

	sharedKey, err := privKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate client tunnel key: %w", err)
	}

	return newEncryptedTunnel(buffered, sharedKey, false)
}

// NewEncryptedPacketConn derives directional AEAD contexts from one shared key and wraps a PacketConn.
func NewEncryptedPacketConn(pc net.PacketConn, sharedKey []byte, isClient bool) (*EncryptedPacketConn, error) {
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

	return &EncryptedPacketConn{
		pc:          pc,
		readAEAD:    readAEAD,
		writeAEAD:   writeAEAD,
		readPrefix:  readPrefix,
		writePrefix: writePrefix,
	}, nil
}

// newEncryptedTunnel derives directional AEAD contexts from one shared key.
func newEncryptedTunnel(stream io.ReadWriteCloser, sharedKey []byte, isClient bool) (*EncryptedTunnel, error) {
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

	return &EncryptedTunnel{
		stream:      stream,
		readAEAD:    readAEAD,
		writeAEAD:   writeAEAD,
		readPrefix:  readPrefix,
		writePrefix: writePrefix,
	}, nil
}

// deriveTunnelMaterial splits the shared key into per-direction key and nonce material.
func deriveTunnelMaterial(sharedKey []byte, label string) ([]byte, [4]byte) {
	keyHash := sha256.Sum256(append(append([]byte{}, sharedKey...), []byte(" key "+label)...))
	prefixHash := sha256.Sum256(append(append([]byte{}, sharedKey...), []byte(" nonce "+label)...))
	var prefix [4]byte
	copy(prefix[:], prefixHash[:4])
	return keyHash[:], prefix
}

// newTunnelAEAD constructs the AES-GCM instance used to protect tunnel frames.
func newTunnelAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aes-gcm: %w", err)
	}
	return aead, nil
}

// writeTunnelClientHello sends the encapsulated ML-KEM payload to the peer.
func writeTunnelClientHello(stream io.ReadWriteCloser, ciphertext []byte) error {
	header := make([]byte, 0, 4+1+2+len(ciphertext))
	header = append(header, encryptedTunnelMagic...)
	header = append(header, encryptedTunnelVersion)
	header = binary.BigEndian.AppendUint16(header, uint16(len(ciphertext)))
	header = append(header, ciphertext...)

	if err := common.WriteFullRetry(stream, header); err != nil {
		return fmt.Errorf("failed to write encrypted tunnel hello: %w", err)
	}
	return nil
}

// readTunnelClientHello reads the encapsulated ML-KEM payload from the peer.
func readTunnelClientHello(stream io.ReadWriteCloser) ([]byte, error) {
	header := make([]byte, 7)
	if _, err := common.ReadFullRetry(stream, header); err != nil {
		return nil, fmt.Errorf("failed to read encrypted tunnel hello header: %w", err)
	}
	magic := []byte(encryptedTunnelMagic)
	if !bytes.Equal(header[:4], magic) {
		return nil, fmt.Errorf("invalid encrypted tunnel magic: got=%q hex=%s", string(header[:4]), hex.EncodeToString(header))
	}
	if header[4] != encryptedTunnelVersion {
		return nil, fmt.Errorf("unsupported encrypted tunnel version %d", header[4])
	}

	cipherLen := binary.BigEndian.Uint16(header[5:7])
	if cipherLen == 0 {
		return nil, errors.New("encrypted tunnel ciphertext is empty")
	}

	ciphertext := make([]byte, cipherLen)
	if _, err := common.ReadFullRetry(stream, ciphertext); err != nil {
		return nil, fmt.Errorf("failed to read encrypted tunnel ciphertext: %w", err)
	}
	return ciphertext, nil
}

// Read decrypts and returns the next plaintext chunk from the stream.
func (t *EncryptedTunnel) Read(p []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	if len(t.readBuf) == 0 {
		frameLenBuf := make([]byte, 4)
		if _, err := common.ReadFullRetry(t.stream, frameLenBuf); err != nil {
			return 0, err
		}

		frameLen := binary.BigEndian.Uint32(frameLenBuf)
		if frameLen == 0 {
			return 0, errors.New("encrypted tunnel frame is empty")
		}

		frame := make([]byte, frameLen)
		if _, err := common.ReadFullRetry(t.stream, frame); err != nil {
			return 0, err
		}

		if uint32(len(frame)) < 12+uint32(t.readAEAD.Overhead()) {
			return 0, errors.New("encrypted tunnel frame too short")
		}
		nonce := frame[:12]
		ciphertext := frame[12:]
		plain, err := t.readAEAD.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return 0, fmt.Errorf("failed to decrypt tunnel frame: %w", err)
		}
		t.readBuf = plain
	}

	n := copy(p, t.readBuf)
	t.readBuf = t.readBuf[n:]
	return n, nil
}

// Write encrypts and sends p over the stream in chunks.
func (t *EncryptedTunnel) Write(p []byte) (int, error) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	for offset := 0; offset < len(p); {
		end := offset + maxTunnelPlainChunk
		if end > len(p) {
			end = len(p)
		}
		chunk := p[offset:end]

		var nonce [12]byte
		copy(nonce[:4], t.writePrefix[:])
		if _, err := crand.Read(nonce[4:]); err != nil {
			return offset, err
		}
		ciphertext := t.writeAEAD.Seal(nil, nonce[:], chunk, nil)

		// Write header + frame as one buffer so they form a single DTLS record.
		out := make([]byte, 0, 4+12+len(ciphertext))
		out = binary.BigEndian.AppendUint32(out, uint32(12+len(ciphertext)))
		out = append(out, nonce[:]...)
		out = append(out, ciphertext...)

		if err := common.WriteFullRetry(t.stream, out); err != nil {
			return offset, err
		}

		offset = end
	}
	return len(p), nil
}

// Underlying returns the raw stream beneath the encryption layer.
// Safe to use only after the handshake is complete and no buffered data remains in readBuf.
func (t *EncryptedTunnel) Underlying() io.ReadWriteCloser {
	return t.stream
}

// Close closes the underlying stream.
func (t *EncryptedTunnel) Close() error {
	return t.stream.Close()
}

// ReadFrom decrypts an incoming packet and returns the plaintext.
func (c *EncryptedPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Need buffer to hold encrypted packet because decrypted size smaller.
	tmp := make([]byte, len(p)+12+c.readAEAD.Overhead())
	n, addr, err = c.pc.ReadFrom(tmp)
	if err != nil {
		return 0, addr, err
	}
	if n < 12+c.readAEAD.Overhead() {
		return 0, addr, errors.New("encrypted packet too short")
	}
	var nonce [12]byte
	copy(nonce[:], tmp[:12])
	plain, openErr := c.readAEAD.Open(nil, nonce[:], tmp[12:n], nil)
	if openErr != nil {
		return 0, addr, fmt.Errorf("failed to decrypt packet: %w", openErr)
	}
	if len(plain) > len(p) {
		return 0, addr, io.ErrShortBuffer
	}
	copy(p, plain)
	return len(plain), addr, nil
}

// WriteTo encrypts p and sends it to addr.
func (c *EncryptedPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var nonce [12]byte
	copy(nonce[:4], c.writePrefix[:])
	if _, err := crand.Read(nonce[4:]); err != nil {
		return 0, err
	}
	ct := c.writeAEAD.Seal(nil, nonce[:], p, nil)
	packet := make([]byte, 0, 12+len(ct))
	packet = append(packet, nonce[:]...)
	packet = append(packet, ct...)
	if _, err := c.pc.WriteTo(packet, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying PacketConn.
func (c *EncryptedPacketConn) Close() error { return c.pc.Close() }

// LocalAddr returns the local network address.
func (c *EncryptedPacketConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr()
}

// SetDeadline sets the read and write deadline.
func (c *EncryptedPacketConn) SetDeadline(t time.Time) error { return c.pc.SetDeadline(t) }

// SetReadDeadline sets the deadline for future reads.
func (c *EncryptedPacketConn) SetReadDeadline(t time.Time) error {
	return c.pc.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future writes.
func (c *EncryptedPacketConn) SetWriteDeadline(t time.Time) error {
	return c.pc.SetWriteDeadline(t)
}

// tunnelConn exposes the wrapped net.Conn when the underlying stream supports it.
func (t *EncryptedTunnel) tunnelConn() (net.Conn, bool) {
	conn, ok := t.stream.(net.Conn)
	return conn, ok
}

// LocalAddr returns the local network address if the underlying stream is a net.Conn.
func (t *EncryptedTunnel) LocalAddr() net.Addr {
	if conn, ok := t.tunnelConn(); ok {
		return conn.LocalAddr()
	}
	return nil
}

// RemoteAddr returns the remote network address if the underlying stream is a net.Conn.
func (t *EncryptedTunnel) RemoteAddr() net.Addr {
	if conn, ok := t.tunnelConn(); ok {
		return conn.RemoteAddr()
	}
	return nil
}

// SetDeadline sets the deadline on the underlying net.Conn.
func (t *EncryptedTunnel) SetDeadline(deadline time.Time) error {
	if conn, ok := t.tunnelConn(); ok {
		return conn.SetDeadline(deadline)
	}
	return nil
}

// SetReadDeadline sets the read deadline on the underlying net.Conn.
func (t *EncryptedTunnel) SetReadDeadline(deadline time.Time) error {
	if conn, ok := t.tunnelConn(); ok {
		return conn.SetReadDeadline(deadline)
	}
	return nil
}

// SetWriteDeadline sets the write deadline on the underlying net.Conn.
func (t *EncryptedTunnel) SetWriteDeadline(deadline time.Time) error {
	if conn, ok := t.tunnelConn(); ok {
		return conn.SetWriteDeadline(deadline)
	}
	return nil
}

// Note: EncryptedTunnel is now stateless w.r.t. packet order/loss by using per-frame random nonces
// (prefixed for direction separation). This is safe for AES-GCM as long as nonces never repeat for a key.

// ClientKEMExchange performs a KEM encapsulation for the given base64 server public key.
// Returns (sharedKey, kemCiphertext, error).
func ClientKEMExchange(serverPubKeyB64 string) (sharedKey []byte, ciphertext []byte, err error) {
	pubBytes, err := base64.StdEncoding.DecodeString(serverPubKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode server public key: %w", err)
	}
	pubKey, err := mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid server public key: %w", err)
	}
	sharedKey, ct := pubKey.Encapsulate()
	return sharedKey, ct, nil
}

// ServerKEMDecapsulate decapsulates a KEM ciphertext using the server private key.
func ServerKEMDecapsulate(serverPrivKeyB64 string, ciphertext []byte) (sharedKey []byte, err error) {
	privBytes, err := base64.StdEncoding.DecodeString(serverPrivKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server private key: %w", err)
	}
	privKey, err := mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid server private key: %w", err)
	}
	sharedKey, err = privKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate: %w", err)
	}
	return sharedKey, nil
}

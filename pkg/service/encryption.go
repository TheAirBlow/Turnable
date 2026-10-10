package service

import (
	"crypto/cipher"
	"crypto/mlkem"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/theairblow/turnable/pkg/connection"
)

// KeyPair holds a parsed ML-KEM768 keypair for service encryption
type KeyPair struct {
	pubKeyBytes []byte                     // encoded public key
	privKey     *mlkem.DecapsulationKey768 // private key
}

// NewKeyPair parses a base64-encoded ML-KEM768 keypair
func NewKeyPair(pubKeyB64, privKeyB64 string) (*KeyPair, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	if _, err := mlkem.NewEncapsulationKey768(pubBytes); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	privKey, err := mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	return &KeyPair{pubKeyBytes: pubBytes, privKey: privKey}, nil
}

// serviceEncLayer provides directional AES-256-GCM-12 encryption over byte slices
type serviceEncLayer struct {
	readAEAD    cipher.AEAD // decrypts incoming frames
	writeAEAD   cipher.AEAD // encrypts outgoing frames
	readPrefix  [4]byte     // nonce prefix for incoming frames
	writePrefix [4]byte     // nonce prefix for outgoing frames
	writeSeq    uint64      // next outgoing frame counter
	readSeq     uint64      // next expected incoming frame counter
}

// newServiceEncLayer derives directional AEAD contexts from the shared key
func newServiceEncLayer(sharedKey []byte, isClient bool) *serviceEncLayer {
	clientKey, clientPrefix := connection.DeriveTunnelMaterial(sharedKey, "client->server")
	serverKey, serverPrefix := connection.DeriveTunnelMaterial(sharedKey, "server->client")

	var readKey, writeKey []byte
	var readPrefix, writePrefix [4]byte
	if isClient {
		writeKey, writePrefix = clientKey, clientPrefix
		readKey, readPrefix = serverKey, serverPrefix
	} else {
		writeKey, writePrefix = serverKey, serverPrefix
		readKey, readPrefix = clientKey, clientPrefix
	}

	rAEAD, _ := connection.NewTunnelAEAD(readKey)
	wAEAD, _ := connection.NewTunnelAEAD(writeKey)

	return &serviceEncLayer{
		readAEAD:    rAEAD,
		writeAEAD:   wAEAD,
		readPrefix:  readPrefix,
		writePrefix: writePrefix,
	}
}

// encrypt encrypts a plain byte slice
func (e *serviceEncLayer) encrypt(plain []byte) []byte {
	var nonce [12]byte
	copy(nonce[:4], e.writePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:], e.writeSeq)
	e.writeSeq++
	out := make([]byte, 8, 8+len(plain)+e.writeAEAD.Overhead())
	copy(out, nonce[4:])
	return e.writeAEAD.Seal(out, nonce[:], plain, nil)
}

// decrypt decrypts a plain byte slice
func (e *serviceEncLayer) decrypt(data []byte) ([]byte, error) {
	if len(data) < 8+e.readAEAD.Overhead() {
		return nil, fmt.Errorf("encrypted payload too short (%d bytes)", len(data))
	}

	if seq := binary.BigEndian.Uint64(data[:8]); seq != e.readSeq {
		return nil, fmt.Errorf("unexpected sequence number %d (want %d)", seq, e.readSeq)
	}

	var nonce [12]byte
	copy(nonce[:4], e.readPrefix[:])
	copy(nonce[4:], data[:8])
	plain, err := e.readAEAD.Open(nil, nonce[:], data[8:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	e.readSeq++
	return plain, nil
}

// encryptedConn wraps a net.Conn with transparent encryption/decryption
type encryptedConn struct {
	nc      net.Conn         // underlying connection
	enc     *serviceEncLayer // frame encryption
	readMu  sync.Mutex       // serializes reads
	writeMu sync.Mutex       // serializes writes
	readBuf []byte           // decrypted bytes not yet returned
	readPos int              // read position in readBuf
	readEnd int              // end of valid data in readBuf
}

// newEncryptedConn wraps a conn with encryption layer
func newEncryptedConn(nc net.Conn, enc *serviceEncLayer) *encryptedConn {
	return &encryptedConn{
		nc:      nc,
		enc:     enc,
		readBuf: make([]byte, 0, 1024),
	}
}

// Read decrypts data transparently
func (ec *encryptedConn) Read(p []byte) (int, error) {
	ec.readMu.Lock()
	defer ec.readMu.Unlock()

	if ec.readPos >= ec.readEnd {
		var lenBuf [4]byte
		if _, err := io.ReadFull(ec.nc, lenBuf[:]); err != nil {
			return 0, err
		}

		size := binary.BigEndian.Uint32(lenBuf[:])
		if size > 8*1024*1024 {
			return 0, fmt.Errorf("encrypted chunk too large: %d bytes", size)
		}

		encData := make([]byte, size)
		if _, err := io.ReadFull(ec.nc, encData); err != nil {
			return 0, err
		}

		plain, err := ec.enc.decrypt(encData)
		if err != nil {
			return 0, err
		}

		ec.readBuf = plain
		ec.readPos = 0
		ec.readEnd = len(plain)
	}

	n := copy(p, ec.readBuf[ec.readPos:ec.readEnd])
	ec.readPos += n
	return n, nil
}

// Write encrypts data transparently
func (ec *encryptedConn) Write(p []byte) (int, error) {
	ec.writeMu.Lock()
	defer ec.writeMu.Unlock()

	encrypted := ec.enc.encrypt(p)

	frame := make([]byte, 4, 4+len(encrypted))
	binary.BigEndian.PutUint32(frame, uint32(len(encrypted)))
	frame = append(frame, encrypted...)

	if _, err := ec.nc.Write(frame); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close closes the underlying connection
func (ec *encryptedConn) Close() error {
	return ec.nc.Close()
}

// LocalAddr returns the underlying local address
func (ec *encryptedConn) LocalAddr() net.Addr {
	return ec.nc.LocalAddr()
}

// RemoteAddr returns the underlying remote address
func (ec *encryptedConn) RemoteAddr() net.Addr {
	return ec.nc.RemoteAddr()
}

// SetDeadline sets deadline on underlying connection
func (ec *encryptedConn) SetDeadline(t time.Time) error {
	return ec.nc.SetDeadline(t)
}

// SetReadDeadline sets read deadline on underlying connection
func (ec *encryptedConn) SetReadDeadline(t time.Time) error {
	return ec.nc.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline on underlying connection
func (ec *encryptedConn) SetWriteDeadline(t time.Time) error {
	return ec.nc.SetWriteDeadline(t)
}

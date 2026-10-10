package mpath

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Version represents the mpath protocol version
const Version byte = 1

const (
	magic = "TMP1" // handshake magic

	kindHello     byte = 0xA1 // client -> server: open a new session
	kindHelloAck  byte = 0xA2 // server -> client: session keys confirmed
	kindAttach    byte = 0xA3 // client -> server: bind this path to a session
	kindAttachAck byte = 0xA4 // server -> client: path bound
	kindReject    byte = 0xA5 // server -> client: version mismatch or unknown session

	sessionIDLen = 16                // random session identifier length
	nonceLen     = 8                 // explicit per-packet counter
	tagLen       = 16                // AES-GCM tag
	sealOverhead = nonceLen + tagLen // bytes a sealed packet adds to its plaintext
)

// ErrVersion is returned when the remote speaks a different wire version
var ErrVersion = errors.New("mpath: wire protocol version mismatch")

// ErrUnknownSession is returned when the server no longer knows the session being attached to
var ErrUnknownSession = errors.New("mpath: server does not know this session")

// sealer encrypts packets with a monotonically increasing explicit nonce, which can never repeat across paths
type sealer struct {
	aead   cipher.AEAD   // AES-256-GCM for this direction
	prefix [4]byte       // fixed nonce prefix derived with the key
	ctr    atomic.Uint64 // per-packet nonce counter, never reused
}

// opener decrypts packets sealed by the peer's sealer
type opener struct {
	aead   cipher.AEAD // AES-256-GCM for this direction
	prefix [4]byte     // fixed nonce prefix derived with the key
}

// newAEAD creates an AES-GCM AEAD from a raw key
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal appends nonce || ciphertext of plain to dst
func (s *sealer) seal(dst, plain []byte) []byte {
	ctr := s.ctr.Add(1)
	var nonce [12]byte
	copy(nonce[:4], s.prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], ctr)
	dst = append(dst, nonce[4:]...)
	return s.aead.Seal(dst, nonce[:], plain, nil)
}

// open decrypts a sealed packet into dst
func (o *opener) open(dst, pkt []byte) ([]byte, error) {
	if len(pkt) < sealOverhead {
		return nil, errors.New("mpath: short packet")
	}
	var nonce [12]byte
	copy(nonce[:4], o.prefix[:])
	copy(nonce[4:], pkt[:nonceLen])
	return o.aead.Open(dst, nonce[:], pkt[nonceLen:], nil)
}

// keys holds both directions of a session
type keys struct {
	send *sealer // seals outgoing packets
	recv *opener // opens incoming packets
}

// deriveKeys derives both directions' AEADs from the handshake secret
func deriveKeys(secret, sessionID []byte, isClient bool) (*keys, error) {
	derive := func(label string) (cipher.AEAD, [4]byte, error) {
		var prefix [4]byte
		out, err := hkdf.Key(sha256.New, secret, sessionID, "turnable mpath "+label, 36)
		if err != nil {
			return nil, prefix, err
		}
		copy(prefix[:], out[32:])
		a, err := newAEAD(out[:32])
		return a, prefix, err
	}
	c2s, c2sPrefix, err := derive("c2s")
	if err != nil {
		return nil, err
	}
	s2c, s2cPrefix, err := derive("s2c")
	if err != nil {
		return nil, err
	}
	k := &keys{}
	if isClient {
		k.send = &sealer{aead: c2s, prefix: c2sPrefix}
		k.recv = &opener{aead: s2c, prefix: s2cPrefix}
	} else {
		k.send = &sealer{aead: s2c, prefix: s2cPrefix}
		k.recv = &opener{aead: c2s, prefix: c2sPrefix}
	}
	return k, nil
}

// ServerKey is the server's static ML-KEM-768 decapsulation key
type ServerKey struct {
	dk *mlkem.DecapsulationKey768 // ML-KEM-768 decapsulation key
}

// ParseServerKey decodes a base64 ML-KEM-768 private key as stored in the server config
func ParseServerKey(b64 string) (*ServerKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server private key: %w", err)
	}
	dk, err := mlkem.NewDecapsulationKey768(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid server private key: %w", err)
	}
	return &ServerKey{dk: dk}, nil
}

// PublicKey returns the matching base64 public key
func (k *ServerKey) PublicKey() string {
	return base64.StdEncoding.EncodeToString(k.dk.EncapsulationKey().Bytes())
}

// clientHandshake is the client half of the hybrid ML-KEM + X25519 handshake
type clientHandshake struct {
	sessionID []byte           // random session identifier sent in the hello
	hello     []byte           // encoded hello packet, resent until acked
	kemShared []byte           // ML-KEM shared secret
	eph       *ecdh.PrivateKey // ephemeral X25519 key for forward secrecy
}

// newClientHandshake builds the hello for a server pinned by its base64 public key
func newClientHandshake(serverPub string) (*clientHandshake, error) {
	raw, err := base64.StdEncoding.DecodeString(serverPub)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server public key: %w", err)
	}
	ek, err := mlkem.NewEncapsulationKey768(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, ct := ek.Encapsulate()
	h := &clientHandshake{sessionID: make([]byte, sessionIDLen), kemShared: shared, eph: eph}
	_, _ = rand.Read(h.sessionID)

	// kind | magic | version | sessionID | x25519 pub | kem ciphertext
	h.hello = append([]byte{kindHello}, magic...)
	h.hello = append(h.hello, Version)
	h.hello = append(h.hello, h.sessionID...)
	h.hello = append(h.hello, eph.PublicKey().Bytes()...)
	h.hello = append(h.hello, ct...)
	return h, nil
}

// finish validates a HelloAck and returns the session keys
func (h *clientHandshake) finish(pkt []byte) (*keys, error) {
	if len(pkt) < 1+sessionIDLen+32+sealOverhead || pkt[0] != kindHelloAck {
		return nil, errors.New("mpath: malformed hello ack")
	}
	if string(pkt[1:1+sessionIDLen]) != string(h.sessionID) {
		return nil, errors.New("mpath: hello ack for another session")
	}
	srvPub, err := ecdh.X25519().NewPublicKey(pkt[1+sessionIDLen : 1+sessionIDLen+32])
	if err != nil {
		return nil, err
	}
	dh, err := h.eph.ECDH(srvPub)
	if err != nil {
		return nil, err
	}
	k, err := deriveKeys(append(append([]byte{}, h.kemShared...), dh...), h.sessionID, true)
	if err != nil {
		return nil, err
	}
	conf, err := k.recv.open(nil, pkt[1+sessionIDLen+32:])
	if err != nil || string(conf) != magic {
		return nil, errors.New("mpath: server failed key confirmation (wrong server key?)")
	}
	return k, nil
}

// serverHello processes a Hello and returns the session ID, keys and HelloAck to send
func (k *ServerKey) serverHello(pkt []byte) ([]byte, *keys, []byte, error) {
	const kemCTLen = mlkem.CiphertextSize768
	if len(pkt) < 1+len(magic)+1 || pkt[0] != kindHello || string(pkt[1:1+len(magic)]) != magic {
		return nil, nil, nil, errors.New("mpath: malformed hello")
	}
	if pkt[1+len(magic)] != Version {
		return nil, nil, nil, fmt.Errorf("%w: client %d, server %d", ErrVersion, pkt[1+len(magic)], Version)
	}
	body := pkt[2+len(magic):]
	if len(body) != sessionIDLen+32+kemCTLen {
		return nil, nil, nil, errors.New("mpath: malformed hello")
	}
	sid := append([]byte{}, body[:sessionIDLen]...)
	cliPub, err := ecdh.X25519().NewPublicKey(body[sessionIDLen : sessionIDLen+32])
	if err != nil {
		return nil, nil, nil, err
	}
	kemShared, err := k.dk.Decapsulate(body[sessionIDLen+32:])
	if err != nil {
		return nil, nil, nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	dh, err := eph.ECDH(cliPub)
	if err != nil {
		return nil, nil, nil, err
	}
	ks, err := deriveKeys(append(kemShared, dh...), sid, false)
	if err != nil {
		return nil, nil, nil, err
	}
	ack := append([]byte{kindHelloAck}, sid...)
	ack = append(ack, eph.PublicKey().Bytes()...)
	ack = ks.send.seal(ack, []byte(magic))
	return sid, ks, ack, nil
}

// attachPacket builds kind | sessionID | sealed(unix time), proving key possession
func attachPacket(sid []byte, k *keys, now time.Time) []byte {
	p := append([]byte{kindAttach}, sid...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(now.Unix()))
	return k.send.seal(p, ts[:])
}

// rejectPacket builds a reject packet carrying the server's version and a reason
func rejectPacket(reason byte) []byte { return []byte{kindReject, Version, reason} }

const (
	rejectVersion byte = 1 // client speaks another wire version
	rejectUnknown byte = 2 // server does not know the session
)

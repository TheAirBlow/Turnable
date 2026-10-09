package protocol

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand/v2"
	"sync"
)

// Masking replaces the outer SRTP/DTLS record encryption once the payload is already encrypted
// end to end (relay mpath mode). The DTLS handshake still runs for the disguise; afterwards each
// record keeps its wire shape but only the first maskPrefix bytes of the payload are XORed with an
// AES-CTR keystream, which hides the inner nonce and header. Payloads whose first byte is not zero
// (inner handshake packets) are masked entirely. Random bytes stand in for the auth tag so packet
// sizes match the real profile.

const (
	maskPrefix   = 32 // bytes masked on inner short-header packets
	maskLabel    = "EXTRACTOR-turnable-mask"
	maskHelloLen = 10
)

var (
	maskHello = [maskHelloLen]byte{0, 0, 'T', 'M', 'A', 'S', 'K', 'v', '1', '?'}
	maskAck   = [maskHelloLen]byte{0, 0, 'T', 'M', 'A', 'S', 'K', 'v', '1', '!'}
)

type maskCtxKey struct{}

// WithMasking asks Connect to negotiate cheap masking instead of full record encryption.
// Only use it when everything written to the conn is already encrypted and authenticated.
func WithMasking(ctx context.Context) context.Context {
	return context.WithValue(ctx, maskCtxKey{}, true)
}

func maskingRequested(ctx context.Context) bool {
	v, _ := ctx.Value(maskCtxKey{}).(bool)
	return v
}

// MaskState reports whether a conn negotiated masking; implemented by protocol conns
type MaskState interface {
	Masked() bool
}

// keyExporter is satisfied by a completed DTLS connection state
type keyExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// masker holds both directions' masking keys
type masker struct {
	send, recv cipher.Block

	tagMu sync.Mutex
	tag   *rand.ChaCha8
}

func newMasker(exp keyExporter, isClient bool) (*masker, error) {
	km, err := exp.ExportKeyingMaterial(maskLabel, nil, 32)
	if err != nil {
		return nil, err
	}
	c2s, err := aes.NewCipher(km[:16])
	if err != nil {
		return nil, err
	}
	s2c, err := aes.NewCipher(km[16:])
	if err != nil {
		return nil, err
	}
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		return nil, err
	}
	m := &masker{tag: rand.NewChaCha8(seed)}
	if isClient {
		m.send, m.recv = c2s, s2c
	} else {
		m.send, m.recv = s2c, c2s
	}
	return m, nil
}

// xorKeystream XORs buf with the CTR keystream for (ssrc, index), starting at block startBlock
func xorKeystream(block cipher.Block, ssrc uint32, index uint64, startBlock int, buf []byte) {
	var iv, ks [16]byte
	binary.BigEndian.PutUint32(iv[4:], ssrc)
	binary.BigEndian.PutUint64(iv[6:], index<<16) // 48-bit index in bytes 8..13, block counter in 14..15
	binary.BigEndian.PutUint32(iv[4:], ssrc)
	for off := 0; off < len(buf); off += 16 {
		binary.BigEndian.PutUint16(iv[14:], uint16(startBlock+off/16))
		block.Encrypt(ks[:], iv[:])
		end := min(off+16, len(buf))
		for i := off; i < end; i++ {
			buf[i] ^= ks[i-off]
		}
	}
}

// maskInPlace masks payload for sending. Index must never repeat for a key.
func (m *masker) maskInPlace(ssrc uint32, index uint64, payload []byte) {
	if len(payload) == 0 {
		return
	}
	n := len(payload)
	if payload[0] == 0 {
		n = min(n, maskPrefix)
	}
	xorKeystream(m.send, ssrc, index, 0, payload[:n])
}

// unmaskInPlace reverses maskInPlace
func (m *masker) unmaskInPlace(ssrc uint32, index uint64, payload []byte) {
	if len(payload) == 0 {
		return
	}
	n := min(len(payload), maskPrefix)
	xorKeystream(m.recv, ssrc, index, 0, payload[:n])
	if payload[0] != 0 && len(payload) > maskPrefix {
		// a fully masked packet: the keystream continues at the next block
		xorKeystream(m.recv, ssrc, index, maskPrefix/16, payload[maskPrefix:])
	}
}

// fillTag writes random bytes standing in for an auth tag
func (m *masker) fillTag(b []byte) {
	m.tagMu.Lock()
	_, _ = m.tag.Read(b)
	m.tagMu.Unlock()
}

// rocTracker estimates the rollover counter of a received 16-bit sequence (RFC 3711 3.3.1)
type rocTracker struct {
	init    bool
	roc     uint32
	highest uint16
}

func (r *rocTracker) index(seq uint16) uint64 {
	if !r.init {
		r.init, r.highest = true, seq
		return uint64(seq)
	}
	v := r.roc
	if r.highest < 32768 {
		if int(seq)-int(r.highest) > 32768 && v > 0 {
			v--
		}
	} else if int(r.highest)-32768 > int(seq) {
		v++
	}
	if v == r.roc && seq > r.highest || v > r.roc {
		r.roc, r.highest = v, seq
	}
	return uint64(v)<<16 | uint64(seq)
}


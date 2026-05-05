package service

import (
	"crypto/mlkem"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	pb "github.com/theairblow/turnable/pkg/service/proto"
	"google.golang.org/protobuf/proto"
)

const (
	serviceVersion = uint32(1) // Server protocol version
)

// writeFramed writes a length-prefixed proto message without encryption
func writeFramed(nc net.Conn, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := nc.Write(lenBuf[:]); err != nil {
		return err
	}

	_, err = nc.Write(data)
	return err
}

// readFramed reads a length-prefixed proto message without decryption
func readFramed(nc net.Conn, msg proto.Message) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(nc, lenBuf[:]); err != nil {
		return err
	}

	size := binary.BigEndian.Uint32(lenBuf[:])
	if size > 8*1024*1024 {
		return fmt.Errorf("message too large: %d bytes", size)
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(nc, data); err != nil {
		return err
	}

	return proto.Unmarshal(data, msg)
}

// serverHandshake sends ServerHello and negotiates encryption, returns wrapped conn and client public key
func serverHandshake(nc net.Conn, kp *KeyPair, allowedKeys [][]byte) (net.Conn, []byte, error) {
	hello := &pb.ServerHello{
		Magic:        "TSVC",
		Version:      serviceVersion,
		AuthRequired: kp != nil,
	}
	if kp != nil {
		hello.PublicKey = kp.pubKeyBytes
	}

	if err := writeFramed(nc, hello); err != nil {
		return nil, nil, fmt.Errorf("write server hello: %w", err)
	}
	if kp == nil {
		return nc, nil, nil
	}

	var clientHello pb.ClientHello
	if err := readFramed(nc, &clientHello); err != nil {
		return nil, nil, fmt.Errorf("read client hello: %w", err)
	}

	if len(allowedKeys) > 0 {
		allowed := false
		for _, k := range allowedKeys {
			if len(k) == len(clientHello.PublicKey) && len(k) > 0 {
				match := true
				for i := range k {
					if k[i] != clientHello.PublicKey[i] {
						match = false
						break
					}
				}
				if match {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return nil, nil, fmt.Errorf("client public key not in allowlist")
		}
	}

	sharedKey, err := kp.privKey.Decapsulate(clientHello.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decapsulate: %w", err)
	}

	encLayer := newServiceEncLayer(sharedKey, false)
	return newEncryptedConn(nc, encLayer), clientHello.PublicKey, nil
}

// clientHandshake reads ServerHello and negotiates encryption, returns wrapped conn
func clientHandshake(nc net.Conn, kp *KeyPair) (net.Conn, error) {
	var serverHello pb.ServerHello
	if err := readFramed(nc, &serverHello); err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}

	if serverHello.Magic != "TSVC" {
		return nil, fmt.Errorf("invalid magic: %s", serverHello.Magic)
	}

	if serverHello.Version != serviceVersion {
		return nil, fmt.Errorf("unsupported version: %d", serverHello.Version)
	}

	if !serverHello.AuthRequired {
		return nc, nil
	}

	if kp == nil {
		return nil, fmt.Errorf("server requires auth but no client keypair provided")
	}

	// Encapsulate shared secret using server public key
	encKey, err := mlkem.NewEncapsulationKey768(serverHello.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	sharedKey, ciphertext := encKey.Encapsulate()

	clientHello := &pb.ClientHello{
		Ciphertext: ciphertext,
		PublicKey:  kp.pubKeyBytes,
	}

	if err := writeFramed(nc, clientHello); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}

	encLayer := newServiceEncLayer(sharedKey, true)
	return newEncryptedConn(nc, encLayer), nil
}

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/theairblow/turnable/pkg/common"
	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/config/providers"
	"github.com/theairblow/turnable/pkg/connection"
	"github.com/theairblow/turnable/pkg/mpath"
	"github.com/theairblow/turnable/pkg/platform"
	"github.com/theairblow/turnable/pkg/platform/vk"
	"github.com/theairblow/turnable/pkg/protocol"
	"github.com/theairblow/turnable/pkg/transport"
)

func init() {
	common.ProtocolsHolder = protocol.Handlers
	protocol.Handlers.Register(&protocol.DTLSHandler{})
	common.TransportsHolder = transport.Handlers
	transport.Handlers.Register(&transport.NoneHandler{})
	transport.Handlers.Register(&transport.KCPHandler{})
	common.ConnectionsHolder = connection.Handlers
	connection.Handlers.Register(&Handler{})
	common.PlatformsHolder = platform.Handlers
	platform.Handlers.Register(&vk.Handler{})
	slog.SetDefault(slog.New(slog.DiscardHandler))
}

type relayFixture struct {
	handler *Handler
	addr    *net.UDPAddr
	pub     string
	user    string
	out     <-chan connection.ServerClient
	cancel  context.CancelFunc
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	_, priv, err := mpath.GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := mpath.ParseServerKey(priv)

	// pick a free UDP port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	_ = pc.Close()

	userID := uuid.NewString()
	prov := &providers.RawProvider{}
	raw, _ := json.Marshal(map[string]any{
		"routes": []providers.Route{
			{ID: "tcp", Address: "127.0.0.1", Port: 1, Socket: "tcp", Transport: "kcp", Encryption: "handshake"},
			{ID: "udp", Address: "127.0.0.1", Port: 2, Socket: "udp", Transport: "none", Encryption: "handshake"},
		},
		"users": []providers.User{{UUID: userID, AllowedRoutes: []string{"tcp", "udp"}, Type: "relay", Peers: 4}},
	})
	if err := prov.Update(raw); err != nil {
		t.Fatal(err)
	}

	h := &Handler{}
	h.SetLogger(slog.Default())
	cfg := &ServerConfig{Proto: "dtls", PubKey: key.PublicKey(), PrivKey: priv, ListenAddr: addr.String()}
	if err := h.Start(cfg, prov); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	out, err := h.AcceptClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = h.Stop()
	})
	return &relayFixture{handler: h, addr: addr, pub: key.PublicKey(), user: userID, out: out, cancel: cancel}
}

func (f *relayFixture) clientConfig() *ClientConfig {
	return &ClientConfig{
		ClientConfig: config.ClientConfig{
			Type: "relay", UserUUID: f.user, PlatformID: "vk", CallID: "x",
			Routes: []config.ClientRoute{{RouteID: "tcp", Socket: "tcp", Transport: "kcp"}, {RouteID: "udp", Socket: "udp"}},
		},
		Gateway: f.addr.String(), Proto: "dtls", Peers: 4, Encryption: "handshake", PubKey: f.pub,
	}
}

func (f *relayFixture) dial(t *testing.T) net.Conn {
	return f.dialMask(t, false)
}

func (f *relayFixture) dialMask(t *testing.T, mask bool) net.Conn {
	t.Helper()
	h, _ := protocol.GetHandler("dtls")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if mask {
		ctx = protocol.WithMasking(ctx)
	}
	c, err := h.Connect(ctx, f.addr, protocol.TURNInfo{}, false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRelayMpathEndToEnd runs a client over several DTLS peers against the real relay server
func TestRelayMpathEndToEnd(t *testing.T) {
	f := newRelayFixture(t)
	cli, err := mpath.NewClient(f.pub, mpath.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := 0; i < 4; i++ {
		c := f.dialMask(t, true)
		if ms, ok := c.(protocol.MaskState); !ok || !ms.Masked() {
			t.Fatal("dtls masking was not negotiated")
		}
		if err := cli.AddPath(ctx, c); err != nil {
			t.Fatalf("add path %d: %v", i, err)
		}
	}
	mux, err := mpath.NewClientMux(cli.Session())
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	if _, err := mpathClientAuth(ctx, mux, f.clientConfig()); err != nil {
		t.Fatalf("auth: %v", err)
	}
	st := &mpathClientState{mux: mux, cfg: f.clientConfig()}

	// tcp route: a stream
	c, err := st.openChannel(0)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("turnable"), 64*1024)
	go func() { _, _ = c.Write(msg) }()
	sc := <-f.out
	if sc.RouteIdx != 0 || sc.User == nil || sc.User.UUID != f.user {
		t.Fatalf("bad server client: %+v", sc)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(sc.Conn, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("stream data mismatch: %v", err)
	}

	// udp route: a datagram flow
	d, err := st.openChannel(1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d.Write([]byte("ping"))
	sd := <-f.out
	if sd.RouteIdx != 1 {
		t.Fatalf("datagram flow on route %d", sd.RouteIdx)
	}
	buf := make([]byte, 64)
	_ = sd.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := sd.Conn.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("datagram mismatch: %q %v", buf[:n], err)
	}
	_, _ = sd.Conn.Write([]byte("pong"))
	_ = d.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = d.Read(buf)
	if err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("datagram reply mismatch: %q %v", buf[:n], err)
	}

	// a stream opened for a udp route must be refused
	bad, _ := mux.OpenStream(1)
	_ = bad.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := bad.Read(buf); err == nil {
		t.Fatal("stream on a udp route was accepted")
	}
}

// TestRelayMpathAuthRejected checks an unknown user gets a rejection, not a hang
func TestRelayMpathAuthRejected(t *testing.T) {
	f := newRelayFixture(t)
	cli, _ := mpath.NewClient(f.pub, mpath.Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := cli.AddPath(ctx, f.dial(t)); err != nil {
		t.Fatal(err)
	}
	mux, _ := mpath.NewClientMux(cli.Session())
	defer mux.Close()
	cfg := f.clientConfig()
	cfg.UserUUID = uuid.NewString()
	_, err := mpathClientAuth(ctx, mux, cfg)
	var rej *ErrAckRejected
	if !errorsAs(err, &rej) {
		t.Fatalf("want ErrAckRejected, got %v", err)
	}
}

// TestRelayLegacyStillServed checks the server still speaks the legacy handshake
func TestRelayLegacyStillServed(t *testing.T) {
	f := newRelayFixture(t)
	raw := f.dial(t)
	enc, err := connection.WrapClientEncryptedConn(raw, f.pub)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.clientConfig()
	cfg.Mux = MuxLegacy
	cfgJSON, _ := cfg.ToJSON(false, true)
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := doClientPrimaryHandshake(enc, cfgJSON); err != nil {
		t.Fatalf("legacy handshake: %v", err)
	}
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }

package service

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theairblow/turnable/pkg/config"
	"github.com/theairblow/turnable/pkg/engine"
	pb "github.com/theairblow/turnable/pkg/service/proto"

	_ "github.com/theairblow/turnable/pkg/init"
)

// testKeys is a base64 encoded ML-KEM-768 keypair
type testKeys struct{ pub, priv string }

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}

	return testKeys{
		pub:  base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes()),
		priv: base64.StdEncoding.EncodeToString(dk.Bytes()),
	}
}

// startTestServer starts a service listening on a Unix socket inside a temp dir
func startTestServer(t *testing.T, cfg config.ServiceConfig) (*Server, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "svc.sock")
	cfg.UnixSocket = sock

	srv, err := NewServer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = srv.Stop() })
	return srv, sock
}

func TestHandshakeRequiresKeyPossession(t *testing.T) {
	server, allowed, impostor := newTestKeys(t), newTestKeys(t), newTestKeys(t)
	_, sock := startTestServer(t, config.ServiceConfig{
		PubKey: server.pub, PrivKey: server.priv, AllowedKeys: []string{allowed.pub},
	})

	good, err := NewClient("unix", sock, ClientOptions{PrivKey: allowed.priv, PubKey: allowed.pub, ServerKey: server.pub})
	if err != nil {
		t.Fatalf("allowed client rejected: %v", err)
	}

	if _, err := good.ListInstances(); err != nil {
		t.Fatalf("request over authenticated connection failed: %v", err)
	}
	_ = good.Close()

	// Claims the allowed public key without holding the matching private key
	if c, err := NewClient("unix", sock, ClientOptions{PrivKey: impostor.priv, PubKey: allowed.pub}); err == nil {
		_ = c.Close()
		t.Fatal("client without the private key was accepted")
	}

	if c, err := NewClient("unix", sock, ClientOptions{PrivKey: impostor.priv, PubKey: impostor.pub}); err == nil {
		_ = c.Close()
		t.Fatal("client with a key outside the allowlist was accepted")
	}
}

func TestClientPinsServerKey(t *testing.T) {
	server, client, other := newTestKeys(t), newTestKeys(t), newTestKeys(t)
	_, sock := startTestServer(t, config.ServiceConfig{PubKey: server.pub, PrivKey: server.priv})

	if c, err := NewClient("unix", sock, ClientOptions{PrivKey: client.priv, PubKey: client.pub, ServerKey: other.pub}); err == nil {
		_ = c.Close()
		t.Fatal("connected to a server with another key than the pinned one")
	}

	_, plain := startTestServer(t, config.ServiceConfig{})
	if c, err := NewClient("unix", plain, ClientOptions{ServerKey: server.pub}); err == nil {
		_ = c.Close()
		t.Fatal("pinned key accepted a server without encryption")
	}
}

func TestReadOnlyKeyCannotChange(t *testing.T) {
	server, admin, reader := newTestKeys(t), newTestKeys(t), newTestKeys(t)
	_, sock := startTestServer(t, config.ServiceConfig{
		PubKey: server.pub, PrivKey: server.priv, AllowedKeys: []string{admin.pub}, ReadonlyKeys: []string{reader.pub},
	})

	c, err := NewClient("unix", sock, ClientOptions{PrivKey: reader.priv, PubKey: reader.pub})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := c.ListProviders(); err != nil {
		t.Fatalf("read-only client cannot read: %v", err)
	}

	err = c.StopInstance("anything")
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only client changed state, got %v", err)
	}
}

func TestStopClosesClients(t *testing.T) {
	srv, sock := startTestServer(t, config.ServiceConfig{})

	c, err := NewClient("unix", sock, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}

	if _, err := c.ListInstances(); err == nil {
		t.Fatal("request succeeded on a stopped service")
	}
}

func TestProviderPersistence(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store.json")
	if err := os.WriteFile(store, []byte(`{"routes":[],"users":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	persist := filepath.Join(dir, "state")
	cfgJSON, _ := json.Marshal(map[string]string{"type": "json", "path": store})

	srv, sock := startTestServer(t, config.ServiceConfig{PersistDir: persist})
	c, err := NewClient("unix", sock, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if ok, err := c.ValidateProviderConfig(`{"type":"json","path":"/nonexistent/store.json"}`); ok || err == nil {
		t.Fatalf("provider with a missing store validated, ok=%v err=%v", ok, err)
	}

	if err := c.AddProvider("p1", "first", string(cfgJSON)); err != nil {
		t.Fatal(err)
	}

	renamed := "second"
	if err := c.UpdateProvider(&pb.UpdateProviderRequest{Uuid: "p1", Name: &renamed}); err != nil {
		t.Fatal(err)
	}

	route := &pb.RouteInfo{Id: "r1", Address: "127.0.0.1", Port: 443, Socket: "udp", Transport: "none", Encryption: "handshake", Name: "r1"}
	if err := c.AddProviderRoute("p1", route); err != nil {
		t.Fatal(err)
	}

	route.Port = 8443
	if err := c.AddProviderRoute("p1", route); err != nil {
		t.Fatalf("replacing a route failed: %v", err)
	}

	routes, err := c.ListProviderRoutes("p1")
	if err != nil || len(routes) != 1 || routes[0].Port != 8443 {
		t.Fatalf("route was not replaced: %v %v", routes, err)
	}

	path := filepath.Join(persist, providersDir, "p1.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if fi.Mode().Perm() != persistFileMode {
		t.Fatalf("persisted provider has mode %v, want %v", fi.Mode().Perm(), os.FileMode(persistFileMode))
	}

	if err := c.UpdateProvider(&pb.UpdateProviderRequest{Uuid: "p1", Config: strPtr(`{"type":"raw"}`)}); err == nil {
		t.Fatal("provider type change was accepted")
	}

	_ = srv.Stop()

	// A new service on the same persist dir brings the provider back
	again, sock2 := startTestServer(t, config.ServiceConfig{PersistDir: persist})
	_ = again
	c2, err := NewClient("unix", sock2, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	p, err := c2.GetProvider("p1")
	if err != nil || p.Name != "second" {
		t.Fatalf("provider was not restored: %v %v", p, err)
	}
}

// testServerConfig returns a valid server config that is never started in tests
func testServerConfig(t *testing.T) string {
	t.Helper()
	k := newTestKeys(t)
	return `{"type":"relay","platform_id":"vk.com","call_id":"1","pub_key":"` + k.pub + `","priv_key":"` + k.priv +
		`","proto":"none","listen_addr":"127.0.0.1:0","public_ip":"127.0.0.1","cloak":"none","provider":"p1"}`
}

func TestStoppedInstanceLifecycle(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store.json")
	if err := os.WriteFile(store, []byte(`{"routes":[],"users":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	persist := filepath.Join(dir, "state")
	cfgJSON, _ := json.Marshal(map[string]string{"type": "json", "path": store})
	record, _ := json.Marshal(persistRecord{
		ID: "s1", Name: "kept", Type: "server", Config: testServerConfig(t), ProviderUUID: "p1", Autostart: false,
	})

	prov, _ := json.Marshal(persistProviderRecord{UUID: "p1", Name: "main", Config: cfgJSON})
	if err := writeFileAtomic(filepath.Join(persist, providersDir, "p1.json"), prov); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(persist, "s1.json"), record); err != nil {
		t.Fatal(err)
	}

	_, sock := startTestServer(t, config.ServiceConfig{PersistDir: persist})
	c, err := NewClient("unix", sock, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Instances without autostart come back stopped instead of vanishing
	got, err := c.GetInstance("s1")
	if err != nil || got.Info.Status != pb.InstanceStatus_INSTANCE_STATUS_STOPPED {
		t.Fatalf("instance was not restored as stopped: %v %v", got, err)
	}

	name, auto := "renamed", true
	if err := c.UpdateInstance(&pb.UpdateInstanceRequest{InstanceId: "s1", Name: &name, Autostart: &auto}); err != nil {
		t.Fatal(err)
	}

	got, err = c.GetInstance("s1")
	if err != nil || got.Info.Name != "renamed" || !got.Info.Autostart || got.Info.Status != pb.InstanceStatus_INSTANCE_STATUS_STOPPED {
		t.Fatalf("metadata change not applied: %v %v", got, err)
	}

	data, err := os.ReadFile(filepath.Join(persist, "s1.json"))
	if err != nil || !strings.Contains(string(data), `"renamed"`) || !strings.Contains(string(data), `"stopped": true`) {
		t.Fatalf("metadata change not persisted: %s %v", data, err)
	}

	if err := c.UpdateInstance(&pb.UpdateInstanceRequest{InstanceId: "s1", ListenAddrs: []string{"127.0.0.1:1"}}); err == nil {
		t.Fatal("listen addresses were accepted for a server instance")
	}

	if err := c.StopInstance("s1"); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(persist, "s1.json")); !os.IsNotExist(err) {
		t.Fatalf("removed instance still persisted: %v", err)
	}
}

func TestCollectUsageAck(t *testing.T) {
	inst := &Instance{server: engine.NewTurnableServer(nil, nil)}
	inst.seedUsage(map[string]engine.Usage{"u": {Up: 1, Down: 2}}, 3)

	// A client that has not seen the restored batch gets it again
	out, token := inst.collectUsage(new(uint64))
	if token != 4 || out["u"] != (engine.Usage{Up: 1, Down: 2}) {
		t.Fatalf("restored batch lost: %v %d", out, token)
	}

	// Confirming the batch clears it
	ack := token
	out, token = inst.collectUsage(&ack)
	if len(out) != 0 || token != 5 {
		t.Fatalf("confirmed batch repeated: %v %d", out, token)
	}

	// A client that never confirms is not given batches twice
	inst.seedUsage(map[string]engine.Usage{"u": {Up: 5}}, 9)
	if out, _ = inst.collectUsage(nil); out["u"].Up != 5 {
		t.Fatalf("batch missing for legacy client: %v", out)
	}

	if out, _ = inst.collectUsage(nil); len(out) != 0 {
		t.Fatalf("legacy client got a batch twice: %v", out)
	}
}

func TestRetryDelayGrowsAndCaps(t *testing.T) {
	prev := time.Duration(0)
	for attempt := int32(0); attempt < 10; attempt++ {
		d := min(retryMinDelay<<min(attempt, 5), retryMaxDelay)
		if d < prev || d > retryMaxDelay {
			t.Fatalf("attempt %d delay %v out of order", attempt, d)
		}
		prev = d
	}

	if prev != retryMaxDelay {
		t.Fatalf("delay never reached the cap, got %v", prev)
	}
}

func strPtr(s string) *string { return &s }

func TestThrottleBlocksRepeatedFailures(t *testing.T) {
	th := newThrottle()
	for i := 0; i < throttleFailures-1; i++ {
		th.fail("10.0.0.1")
	}

	if th.blocked("10.0.0.1") {
		t.Fatal("host blocked before the failure limit")
	}

	th.fail("10.0.0.1")
	if !th.blocked("10.0.0.1") || th.blocked("10.0.0.2") {
		t.Fatal("only the failing host should be blocked")
	}

	th.succeed("10.0.0.1")
	th.fail("")
	if th.blocked("") {
		t.Fatal("Unix socket peers must never be blocked")
	}
}

func TestLateResponseDoesNotAnswerNextRequest(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()

	c := &Client{
		conn:    clientSide,
		respCh:  make(chan *pb.Response, 1),
		eventCh: make(chan Event, 16),
		done:    make(chan struct{}),
		timeout: 100 * time.Millisecond,
	}
	go c.readLoop()
	defer c.Close()

	var first, second pb.Request
	go func() {
		_ = readFramed(serverSide, &first)
		_ = readFramed(serverSide, &second)

		// The reply to the timed out request arrives after the reply to the next one was expected
		_ = writeFramed(serverSide, &pb.Response{RequestId: first.RequestId, Payload: &pb.Response_ListInstances{
			ListInstances: &pb.ListInstancesResponse{Instances: []*pb.InstanceInfo{{Id: "late"}}},
		}})
		_ = writeFramed(serverSide, &pb.Response{RequestId: second.RequestId, Payload: &pb.Response_ListInstances{
			ListInstances: &pb.ListInstancesResponse{Instances: []*pb.InstanceInfo{{Id: "fresh"}}},
		}})
	}()

	if _, err := c.ListInstances(); err == nil {
		t.Fatal("first request should time out")
	}

	got, err := c.ListInstances()
	if err != nil || len(got) != 1 || got[0].Id != "fresh" {
		t.Fatalf("second request got the wrong reply: %v %v", got, err)
	}
}

func TestRestartRevivesStoppedInstance(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store.json")
	if err := os.WriteFile(store, []byte(`{"routes":[],"users":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	persist := filepath.Join(dir, "state")
	cfgJSON, _ := json.Marshal(map[string]string{"type": "json", "path": store})
	prov, _ := json.Marshal(persistProviderRecord{UUID: "p1", Name: "main", Config: cfgJSON})
	record, _ := json.Marshal(persistRecord{
		ID: "s1", Name: "kept", Type: "server", Config: testServerConfig(t), ProviderUUID: "p1", Autostart: true, Stopped: true,
	})
	if err := writeFileAtomic(filepath.Join(persist, providersDir, "p1.json"), prov); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(persist, "s1.json"), record); err != nil {
		t.Fatal(err)
	}

	srv, sock := startTestServer(t, config.ServiceConfig{PersistDir: persist})
	c, err := NewClient("unix", sock, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	srv.mu.RLock()
	before := srv.instances["s1"]
	srv.mu.RUnlock()

	if err := c.RestartInstance("s1"); err != nil {
		t.Fatal(err)
	}

	srv.mu.RLock()
	after := srv.instances["s1"]
	srv.mu.RUnlock()
	if after == before || after.Stopped() {
		t.Fatal("restart did not replace the stopped instance with a live one")
	}

	data, err := os.ReadFile(filepath.Join(persist, "s1.json"))
	if err != nil || strings.Contains(string(data), `"stopped"`) {
		t.Fatalf("revived instance still persisted as stopped: %s %v", data, err)
	}

	// The test config cannot reach VK, so the instance fails and, being autostart, gets replaced again
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.RLock()
		cur := srv.instances["s1"]
		srv.mu.RUnlock()
		if cur != after && !cur.Stopped() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatal("failed autostart instance was never retried")
}

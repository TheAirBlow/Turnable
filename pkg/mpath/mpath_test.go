package mpath

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/theairblow/turnable/pkg/netem"
)

func lossyPaths(n int, loss float64) []*netem.Path {
	return netem.NewPaths(netem.MultiConfig{
		Paths: n, Rate: 300 * 1024,
		MinDelay: 5 * time.Millisecond, MaxDelay: 40 * time.Millisecond,
		Jitter: 3 * time.Millisecond, Loss: loss,
	}, 7)
}

func closePaths(paths []*netem.Path) {
	for _, p := range paths {
		p.Close()
	}
}

// TestStreamIntegrity pushes random data both ways over lossy paths and checks every byte
func TestStreamIntegrity(t *testing.T) {
	paths := lossyPaths(4, 0.05)
	defer closePaths(paths)
	st := newMpathStack(t, paths, Config{})
	defer st.Close()

	const size = 1 << 20
	const streams = 4
	var wg sync.WaitGroup
	sums := make(chan [32]byte, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := <-st.Accept()
			h := sha256.New()
			if _, err := io.CopyN(h, c, size); err != nil {
				t.Errorf("server read: %v", err)
				return
			}
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			sums <- sum
		}()
	}
	want := map[[32]byte]bool{}
	for i := 0; i < streams; i++ {
		data := make([]byte, size)
		_, _ = rand.Read(data)
		want[sha256.Sum256(data)] = true
		c, err := st.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = c.Write(data) }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("transfer timed out")
	}
	close(sums)
	for s := range sums {
		if !want[s] {
			t.Fatal("stream data corrupted")
		}
	}
	if dup := st.server.Session().Stats().DupSegments; dup > 0 {
		t.Logf("duplicate segments: %d", dup)
	}
}

// TestDatagramFragments sends datagrams larger than one packet
func TestDatagramFragments(t *testing.T) {
	paths := lossyPaths(3, 0)
	defer closePaths(paths)
	st := newMpathStack(t, paths, Config{})
	defer st.Close()

	f, _ := st.OpenDatagram()
	var srv net.Conn
	for _, n := range []int{1, 1200, 3000, 9000} {
		msg := make([]byte, n)
		_, _ = rand.Read(msg)
		if _, err := f.Write(msg); err != nil {
			t.Fatal(err)
		}
		if srv == nil {
			srv = <-st.Accept()
		}
		buf := make([]byte, 65536)
		_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := srv.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:got], msg) {
			t.Fatalf("datagram of %d bytes corrupted (got %d)", n, got)
		}
	}
	if _, err := f.Write(make([]byte, 64*1024)); err == nil {
		t.Fatal("oversized datagram accepted")
	}
}

// TestWrongServerKey checks that the client refuses a server that lacks the pinned key
func TestWrongServerKey(t *testing.T) {
	p := netem.NewPath(netem.PathConfig{Delay: time.Millisecond}, 1)
	defer p.Close()
	realKey, _, _ := GenerateServerKey()
	_, otherPriv, _ := GenerateServerKey()
	other, _ := ParseServerKey(otherPriv)

	srv := NewServer(realKey, Config{})
	go func() { _ = srv.HandleConn(context.Background(), p.B) }()
	cli, err := NewClient(other.PublicKey(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cli.AddPath(ctx, p.A); err == nil {
		t.Fatal("handshake with the wrong server key succeeded")
	}
}

// TestVersionMismatch checks that a version bump fails with a clear error
func TestVersionMismatch(t *testing.T) {
	p := netem.NewPath(netem.PathConfig{Delay: time.Millisecond}, 1)
	defer p.Close()
	key, _, _ := GenerateServerKey()
	srv := NewServer(key, Config{})
	go func() { _ = srv.HandleConn(context.Background(), p.B) }()
	cli, _ := NewClient(key.PublicKey(), Config{})
	cli.hs.hello[1+len(magic)] = Version + 1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cli.AddPath(ctx, p.A); !errors.Is(err, ErrVersion) {
		t.Fatalf("want ErrVersion, got %v", err)
	}
}

// TestUnknownSession checks that attaching to a server that lost the session fails cleanly
func TestUnknownSession(t *testing.T) {
	paths := lossyPaths(2, 0)
	defer closePaths(paths)
	key, _, _ := GenerateServerKey()
	srv := NewServer(key, Config{})
	go func() { _ = srv.HandleConn(context.Background(), paths[0].B) }()
	cli, _ := NewClient(key.PublicKey(), Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cli.AddPath(ctx, paths[0].A); err != nil {
		t.Fatal(err)
	}
	restarted := NewServer(key, Config{})
	go func() { _ = restarted.HandleConn(context.Background(), paths[1].B) }()
	if err := cli.AddPath(ctx, paths[1].A); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("want ErrUnknownSession, got %v", err)
	}
	select {
	case <-cli.Session().Done():
	case <-time.After(time.Second):
		t.Fatal("session not closed after unknown-session reject")
	}
}

// TestPathDeathAndRevival blackholes a path, checks it is declared dead, then revived
func TestPathDeathAndRevival(t *testing.T) {
	paths := lossyPaths(3, 0)
	defer closePaths(paths)
	cfg := Config{DeadTimeout: 500 * time.Millisecond, ProbeInterval: 100 * time.Millisecond}
	st := newMpathStack(t, paths, cfg)
	defer st.Close()

	dead := make(chan struct{}, 4)
	st.client.Session().SetPathHandlers(func(_ net.Conn) { dead <- struct{}{} }, nil)

	// keep data flowing so liveness is measured
	stop := make(chan struct{})
	defer close(stop)
	c, _ := st.OpenStream()
	go func() { _, _ = io.Copy(io.Discard, <-st.Accept()) }()
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}()

	time.Sleep(500 * time.Millisecond)
	paths[0].SetDown(true)
	select {
	case <-dead:
	case <-time.After(5 * time.Second):
		t.Fatal("blackholed path never declared dead")
	}
	if n := st.client.Session().AlivePaths(); n != 2 {
		t.Fatalf("alive paths %d, want 2", n)
	}
	paths[0].SetDown(false)
	deadline := time.Now().Add(5 * time.Second)
	for st.client.Session().AlivePaths() != 3 {
		if time.Now().After(deadline) {
			t.Fatal("path not revived")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

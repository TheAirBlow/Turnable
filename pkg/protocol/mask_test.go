package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"net"
	"testing"
	"time"
)

func init() { slog.SetDefault(slog.New(slog.DiscardHandler)) }

func freeUDPAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := pc.LocalAddr().(*net.UDPAddr)
	_ = pc.Close()
	return a
}

// startServer starts h on loopback and returns its accepted conns
func startServer(t *testing.T, h Handler) (*net.UDPAddr, <-chan ServerClient) {
	t.Helper()
	addr := freeUDPAddr(t)
	if err := h.Start(addr.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = h.Stop() })
	ch, err := h.AcceptClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return addr, ch
}

// exchange checks payloads both ways, including ones that look like inner handshake packets
func exchange(t *testing.T, cli, srv net.Conn) {
	t.Helper()
	buf := make([]byte, 2048)
	for _, first := range []byte{0x00, 0xA1} {
		for _, n := range []int{1, 31, 32, 33, 1300} {
			msg := make([]byte, n)
			_, _ = rand.Read(msg)
			msg[0] = first
			for _, dir := range [][2]net.Conn{{cli, srv}, {srv, cli}} {
				if _, err := dir[0].Write(msg); err != nil {
					t.Fatal(err)
				}
				_ = dir[1].SetReadDeadline(time.Now().Add(3 * time.Second))
				got, err := dir[1].Read(buf)
				if err != nil {
					t.Fatalf("read %d bytes: %v", n, err)
				}
				if !bytes.Equal(buf[:got], msg) {
					t.Fatalf("payload of %d bytes (first %#x) corrupted", n, first)
				}
			}
		}
	}
}

func testMasking(t *testing.T, srvH, cliH Handler, mask bool) {
	addr, accepted := startServer(t, srvH)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if mask {
		ctx = WithMasking(ctx)
	}
	type res struct {
		c   net.Conn
		err error
	}
	cr := make(chan res, 1)
	go func() {
		c, err := cliH.Connect(ctx, addr, TURNInfo{}, false)
		cr <- res{c, err}
	}()
	var srv net.Conn
	select {
	case sc := <-accepted:
		srv = sc.Conn
	case <-ctx.Done():
		t.Fatal("no server conn")
	}
	// the server only sees negotiation when it reads, as the relay layer always does
	srvFirst := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := srv.Read(buf)
		if err != nil {
			srvFirst <- nil
			return
		}
		srvFirst <- append([]byte(nil), buf[:n]...)
	}()
	r := <-cr
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.c.Close()
	if _, err := r.c.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if got := <-srvFirst; string(got) != "first" {
		t.Fatalf("first packet %q", got)
	}
	_ = srv.SetReadDeadline(time.Time{})

	if ms, ok := r.c.(MaskState); ok && ms.Masked() != mask {
		t.Fatalf("client masked=%v, want %v", ms.Masked(), mask)
	}
	if ms, ok := srv.(MaskState); ok && ms.Masked() != mask {
		t.Fatalf("server masked=%v, want %v", ms.Masked(), mask)
	}
	exchange(t, r.c, srv)
}

func TestSRTPMasked(t *testing.T)   { testMasking(t, &SRTPHandler{}, &SRTPHandler{}, true) }
func TestSRTPUnmasked(t *testing.T) { testMasking(t, &SRTPHandler{}, &SRTPHandler{}, false) }

func TestROCTracker(t *testing.T) {
	var r rocTracker
	var want uint64
	for i := 0; i < 200000; i++ {
		seq := uint16(want)
		if got := r.index(seq); got != want {
			t.Fatalf("index %d: got %d", want, got)
		}
		want++
	}
	// a late packet from before the last wrap
	late := want - 70
	if got := r.index(uint16(late)); got != late {
		t.Fatalf("late packet: got %d want %d", got, late)
	}
}

func TestDTLSMasked(t *testing.T)   { testMasking(t, &DTLSHandler{}, &DTLSHandler{}, true) }
func TestDTLSUnmasked(t *testing.T) { testMasking(t, &DTLSHandler{}, &DTLSHandler{}, false) }

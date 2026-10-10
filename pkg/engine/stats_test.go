package engine

import (
	"net"
	"testing"
	"time"
)

// newTestServer creates a server that was never started, only good for its books
func newTestServer() *TurnableServer {
	return &TurnableServer{tr: newTracker()}
}

func TestStatsCountAndCollect(t *testing.T) {
	s := newTestServer()
	events, cancel := s.Subscribe(8)
	defer cancel()

	a, b := net.Pipe()
	defer b.Close()
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4000}
	ch := s.tr.open("u1", "sess1", "r1", addr, func() { _ = a.Close() })
	conn := &countConn{Conn: a, ch: ch}

	go func() { _, _ = b.Write([]byte("hello")) }()
	buf := make([]byte, 16)
	if n, _ := conn.Read(buf); n != 5 {
		t.Fatalf("read %d bytes", n)
	}
	go func() { _, _ = b.Read(buf) }()
	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}

	u, ok := s.User("u1")
	if !ok || !u.Online || u.Usage != (Usage{Up: 5, Down: 2}) || len(u.IPs) != 1 || u.IPs[0] != "203.0.113.7" {
		t.Fatalf("user stats %+v", u)
	}
	if got := s.CollectUsage()["u1"]; got != (Usage{Up: 5, Down: 2}) {
		t.Fatalf("collected %+v", got)
	}
	if len(s.CollectUsage()) != 0 {
		t.Fatal("usage was not reset")
	}
	if st := s.Stats(); st.Users != 1 || st.Channels != 1 || st.Sessions != 1 || st.Usage.Up != 5 {
		t.Fatalf("server stats %+v", st)
	}
	if ss := s.Sessions(); len(ss) != 1 || ss[0].ID != "sess1" || ss[0].Channels != 1 {
		t.Fatalf("sessions %+v", ss)
	}

	if n := s.KickUser("u1"); n != 1 {
		t.Fatalf("kicked %d", n)
	}
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("the kicked connection is still open")
	}

	s.tr.done(ch)
	if u, _ := s.User("u1"); u.Online || u.Usage.Up != 5 {
		t.Fatalf("after close %+v", u)
	}
	if len(s.Sessions()) != 0 {
		t.Fatal("session was not dropped")
	}

	if ev := <-events; ev.Type != EventConnect || ev.User != "u1" || ev.Online != 1 {
		t.Fatalf("first event %+v", ev)
	}
	select {
	case ev := <-events:
		if ev.Type != EventDisconnect || ev.Usage.Up != 5 || ev.Online != 0 {
			t.Fatalf("second event %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no disconnect event")
	}
}

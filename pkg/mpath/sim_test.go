package mpath

import (
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// simLink is one direction of a bottleneck shared by every path that uses it
type simLink struct {
	mu       sync.Mutex
	rate     float64                             // bytes/sec
	owd      time.Duration                       // one-way propagation delay
	maxQueue time.Duration                       // drop-tail depth, as queueing time
	extra    func(t time.Duration) time.Duration // additional delay not caused by queueing
	start    time.Time
	free     time.Time // when the serializer is next idle
	lastArr  time.Time
	lost     atomic.Int64
	loss     float64         // random loss probability
	qs       []time.Duration // bottleneck queueing delay seen by each accepted packet
}

func (l *simLink) setRate(r float64) { l.mu.Lock(); l.rate = r; l.mu.Unlock() }

// transmit returns when a packet written now reaches the peer, ok false if dropped
func (l *simLink) transmit(now time.Time, size int) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.loss > 0 && rand.Float64() < l.loss {
		l.lost.Add(1)
		return time.Time{}, false
	}
	if l.free.Before(now) {
		l.free = now
	}
	if l.free.Sub(now) > l.maxQueue {
		l.lost.Add(1)
		return time.Time{}, false
	}
	l.qs = append(l.qs, l.free.Sub(now))
	l.free = l.free.Add(time.Duration(float64(size) / l.rate * float64(time.Second)))
	arr := l.free.Add(l.owd)
	if l.extra != nil {
		arr = arr.Add(l.extra(now.Sub(l.start)))
	}
	if arr.Before(l.lastArr) {
		arr = l.lastArr
	}
	l.lastArr = arr
	return arr, true
}

type simPkt struct {
	at time.Time
	b  []byte
}

// simConn is one end of a packet pipe whose two directions run through simLinks
type simConn struct {
	out    *simLink
	stage  *simLink                          // optional per-path limiter in front of out
	extra  time.Duration                     // this path's own propagation delay beyond the shared link
	wander func(time.Duration) time.Duration // slowly varying delay the path adds
	in     chan simPkt                       // from the peer's link
	peerIn chan simPkt
	closed chan struct{}
	once   sync.Once
}

type simAddr struct{}

func (simAddr) Network() string { return "sim" }
func (simAddr) String() string  { return "sim" }

func (c *simConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	now := time.Now()
	if c.stage != nil {
		at, ok := c.stage.transmit(now, len(b)+28)
		if !ok {
			return len(b), nil
		}
		now = at.Add(-c.stage.owd)
	}
	arr, ok := c.out.transmit(now, len(b)+28)
	if !ok {
		return len(b), nil
	}
	arr = arr.Add(c.extra)
	if c.wander != nil {
		arr = arr.Add(c.wander(arr.Sub(c.out.start)))
	}
	c.peerIn <- simPkt{arr, append([]byte(nil), b...)}
	return len(b), nil
}

func (c *simConn) Read(b []byte) (int, error) {
	select {
	case p := <-c.in:
		if d := time.Until(p.at); d > 0 {
			time.Sleep(d)
		}
		return copy(b, p.b), nil
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *simConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *simConn) LocalAddr() net.Addr              { return simAddr{} }
func (c *simConn) RemoteAddr() net.Addr             { return simAddr{} }
func (c *simConn) SetDeadline(time.Time) error      { return nil }
func (c *simConn) SetReadDeadline(time.Time) error  { return nil }
func (c *simConn) SetWriteDeadline(time.Time) error { return nil }

// simNet is a client and server session joined by paths over a shared bottleneck per direction
type simNet struct {
	up, down           *simLink // client->server, server->client
	cli, srv           *Session
	cliConns, srvConns []*simConn
}

func newSimNet(t testing.TB, nPaths int, up, down *simLink, cfg Config, mkStage func(up bool) *simLink) *simNet {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	secret, id := make([]byte, 32), make([]byte, sessionIDLen)
	kc, err := deriveKeys(secret, id, true)
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := deriveKeys(secret, id, false)
	n := &simNet{up: up, down: down, cli: newSession(&cfg, kc, id, true), srv: newSession(&cfg, ks, id, false)}
	now := time.Now()
	for _, l := range []*simLink{up, down} {
		l.start = now
	}
	for i := 0; i < nPaths; i++ {
		a, b := make(chan simPkt, 1<<16), make(chan simPkt, 1<<16)
		cc := &simConn{out: up, in: a, peerIn: b, closed: make(chan struct{})}
		sc := &simConn{out: down, in: b, peerIn: a, closed: make(chan struct{})}
		if mkStage != nil {
			cc.stage, sc.stage = mkStage(true), mkStage(false)
		}
		n.cliConns, n.srvConns = append(n.cliConns, cc), append(n.srvConns, sc)
		n.cli.attach(cc)
		n.srv.attach(sc)
	}
	t.Cleanup(func() { n.cli.Close(); n.srv.Close() })
	return n
}

// pump writes as fast as the session allows from w to r and returns a counter of bytes read
func pump(w, r *Session) *atomic.Int64 {
	var got atomic.Int64
	go func() {
		buf := make([]byte, 16*1024)
		for {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := r.Read(buf)
			if err != nil {
				return
			}
			got.Add(int64(n))
		}
	}()
	return &got
}

// queuePct returns the p-th percentile of bottleneck queueing delay
func (l *simLink) queuePct(p float64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.qs) == 0 {
		return 0
	}
	c := append([]time.Duration(nil), l.qs...)
	slices.Sort(c)
	return c[int(float64(len(c)-1)*p)]
}

// measure returns the goodput over the last window of a run, bytes/sec
func measure(got *atomic.Int64, dur, window time.Duration, tick func(el time.Duration)) float64 {
	start := time.Now()
	var mark int64
	for el := 100 * time.Millisecond; el <= dur; el += 100 * time.Millisecond {
		time.Sleep(time.Until(start.Add(el)))
		tick(el)
		if el == dur-window {
			mark = got.Load()
		}
	}
	return float64(got.Load()-mark) / window.Seconds()
}

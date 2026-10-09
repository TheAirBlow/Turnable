// Package netem emulates lossy, rate-policed, delayed packet paths for tests and benchmarks
package netem

import (
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// PathConfig describes one direction of an emulated path
type PathConfig struct {
	Rate   float64       // policer rate in bytes/sec, 0 means unlimited
	Burst  int           // policer bucket size in bytes, 0 picks a default
	Delay  time.Duration // base one-way delay
	Jitter time.Duration // uniform extra delay in [0, Jitter), never reorders
	Loss   float64       // random loss probability in [0, 1)
}

// Stats counts what happened to packets on one direction of a path
type Stats struct {
	Sent      atomic.Uint64 // packets offered to the path
	Delivered atomic.Uint64 // packets handed to the receiver
	Policed   atomic.Uint64 // packets dropped by the token bucket
	Lost      atomic.Uint64 // packets dropped by random loss or a downed path
	Overflow  atomic.Uint64 // packets dropped because the receiver buffer was full
	Bytes     atomic.Uint64 // payload bytes delivered
}

const (
	defaultBurst = 16 * 1024 // default policer bucket size
	recvBufPkts  = 4096      // receiver buffer depth in packets
)

var errClosed = errors.New("netem: closed")

// packet is one in-flight datagram
type packet struct {
	data      []byte
	deliverAt time.Time
}

// direction is a one-way FIFO pipe with a policer, delay and loss
type direction struct {
	cfg   PathConfig
	stats *Stats

	mu        sync.Mutex
	tokens    float64
	lastFill  time.Time
	lastDue   time.Time
	down      bool
	rng       *rand.Rand
	inflight  chan packet
	recv      chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func newDirection(cfg PathConfig, seed uint64) *direction {
	if cfg.Burst <= 0 {
		cfg.Burst = defaultBurst
	}
	d := &direction{
		cfg:      cfg,
		stats:    &Stats{},
		tokens:   float64(cfg.Burst),
		lastFill: time.Now(),
		rng:      rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		inflight: make(chan packet, 1<<16),
		recv:     make(chan []byte, recvBufPkts),
		done:     make(chan struct{}),
	}
	go d.deliverLoop()
	return d
}

// send polices and schedules one packet
func (d *direction) send(p []byte) {
	d.stats.Sent.Add(1)
	now := time.Now()

	d.mu.Lock()
	if d.down {
		d.mu.Unlock()
		d.stats.Lost.Add(1)
		return
	}
	if d.cfg.Rate > 0 {
		d.tokens += now.Sub(d.lastFill).Seconds() * d.cfg.Rate
		if d.tokens > float64(d.cfg.Burst) {
			d.tokens = float64(d.cfg.Burst)
		}
		d.lastFill = now
		if d.tokens < float64(len(p)) {
			d.mu.Unlock()
			d.stats.Policed.Add(1)
			return
		}
		d.tokens -= float64(len(p))
	}
	if d.cfg.Loss > 0 && d.rng.Float64() < d.cfg.Loss {
		d.mu.Unlock()
		d.stats.Lost.Add(1)
		return
	}
	due := now.Add(d.cfg.Delay)
	if d.cfg.Jitter > 0 {
		due = due.Add(time.Duration(d.rng.Int64N(int64(d.cfg.Jitter))))
	}
	if due.Before(d.lastDue) {
		due = d.lastDue // keep the path FIFO
	}
	d.lastDue = due
	d.mu.Unlock()

	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case d.inflight <- packet{data: buf, deliverAt: due}:
	case <-d.done:
	default:
		d.stats.Lost.Add(1)
	}
}

// deliverLoop hands packets to the receiver once their delay has elapsed
func (d *direction) deliverLoop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		var pkt packet
		select {
		case pkt = <-d.inflight:
		case <-d.done:
			return
		}
		if wait := time.Until(pkt.deliverAt); wait > 0 {
			timer.Reset(wait)
			select {
			case <-timer.C:
			case <-d.done:
				return
			}
		}
		d.mu.Lock()
		down := d.down
		d.mu.Unlock()
		if down {
			d.stats.Lost.Add(1)
			continue
		}
		select {
		case d.recv <- pkt.data:
			d.stats.Delivered.Add(1)
			d.stats.Bytes.Add(uint64(len(pkt.data)))
		default:
			d.stats.Overflow.Add(1)
		}
	}
}

func (d *direction) setDown(down bool) {
	d.mu.Lock()
	d.down = down
	d.mu.Unlock()
}

func (d *direction) close() {
	d.closeOnce.Do(func() { close(d.done) })
}

// Path is a bidirectional emulated path with two endpoints
type Path struct {
	A, B   *Conn // endpoints; A writes reach B and vice versa
	ab, ba *direction
}

// NewPath creates a path whose two directions share the same config
func NewPath(cfg PathConfig, seed uint64) *Path {
	return NewAsymmetricPath(cfg, cfg, seed)
}

// NewAsymmetricPath creates a path with separate A->B and B->A configs
func NewAsymmetricPath(ab, ba PathConfig, seed uint64) *Path {
	p := &Path{ab: newDirection(ab, seed), ba: newDirection(ba, seed+1)}
	id := pathIDs.Add(1)
	addrA := &Addr{Name: "netem-a", ID: id}
	addrB := &Addr{Name: "netem-b", ID: id}
	p.A = newConn(p.ab, p.ba, addrA, addrB)
	p.B = newConn(p.ba, p.ab, addrB, addrA)
	return p
}

var pathIDs atomic.Uint64

// SetDown blackholes the path in both directions without returning errors, like a silent throttle
func (p *Path) SetDown(down bool) {
	p.ab.setDown(down)
	p.ba.setDown(down)
}

// Close closes both endpoints
func (p *Path) Close() {
	_ = p.A.Close()
	_ = p.B.Close()
}

// StatsAB returns A->B direction counters
func (p *Path) StatsAB() *Stats { return p.ab.stats }

// StatsBA returns B->A direction counters
func (p *Path) StatsBA() *Stats { return p.ba.stats }

// Addr is a fake address that identifies one path endpoint
type Addr struct {
	Name string
	ID   uint64
}

// Network returns the network name
func (a *Addr) Network() string { return "netem" }

// String returns the string form
func (a *Addr) String() string {
	return a.Name + "/" + itoa(a.ID)
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// Conn is one endpoint of a path, implementing a packet-oriented net.Conn
type Conn struct {
	tx, rx        *direction
	local, remote net.Addr

	closed   chan struct{}
	once     sync.Once
	deadline atomic.Pointer[time.Time]
	dlNotify chan struct{}
}

func newConn(tx, rx *direction, local, remote net.Addr) *Conn {
	return &Conn{tx: tx, rx: rx, local: local, remote: remote, closed: make(chan struct{}), dlNotify: make(chan struct{}, 1)}
}

// Read returns the next delivered packet
func (c *Conn) Read(p []byte) (int, error) {
	for {
		var timeout <-chan time.Time
		if dl := c.deadline.Load(); dl != nil && !dl.IsZero() {
			wait := time.Until(*dl)
			if wait <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(wait)
			timeout = t.C
			defer t.Stop()
		}
		select {
		case pkt := <-c.rx.recv:
			return copy(p, pkt), nil
		case <-c.closed:
			return 0, net.ErrClosed
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-c.dlNotify:
		}
	}
}

// Write sends one packet
func (c *Conn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.tx.send(p)
	return len(p), nil
}

// Close closes this endpoint and the path directions it owns
func (c *Conn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.tx.close()
	})
	return nil
}

// LocalAddr returns the fake local address
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns the fake remote address
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets the read deadline; writes never block
func (c *Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

// SetReadDeadline sets the read deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.deadline.Store(&t)
	select {
	case c.dlNotify <- struct{}{}:
	default:
	}
	return nil
}

// SetWriteDeadline is a no-op
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }

// ReadFrom implements net.PacketConn
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.remote, err
}

// WriteTo implements net.PacketConn, ignoring the address
func (c *Conn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

// MultiConfig spreads paths across a delay range
type MultiConfig struct {
	Paths    int           // number of paths
	Rate     float64       // per-path policer rate in bytes/sec
	MinDelay time.Duration // smallest base one-way delay
	MaxDelay time.Duration // largest base one-way delay
	Jitter   time.Duration // per-path jitter
	Loss     float64       // per-path random loss
}

// DefaultMulti returns the acceptance-test topology: 10 paths, ~200 KB/s, 20-150 ms
func DefaultMulti() MultiConfig {
	return MultiConfig{Paths: 10, Rate: 200 * 1024, MinDelay: 20 * time.Millisecond, MaxDelay: 150 * time.Millisecond, Jitter: 5 * time.Millisecond}
}

// NewPaths builds the paths described by cfg
func NewPaths(cfg MultiConfig, seed uint64) []*Path {
	paths := make([]*Path, cfg.Paths)
	for i := range paths {
		delay := cfg.MinDelay
		if cfg.Paths > 1 {
			delay += (cfg.MaxDelay - cfg.MinDelay) * time.Duration(i) / time.Duration(cfg.Paths-1)
		}
		paths[i] = NewPath(PathConfig{Rate: cfg.Rate, Delay: delay, Jitter: cfg.Jitter, Loss: cfg.Loss}, seed+uint64(i)*2)
	}
	return paths
}

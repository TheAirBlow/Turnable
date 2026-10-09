package mpath

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/theairblow/turnable/pkg/netem"
)

func init() {
	if os.Getenv("NETEM_LOG") == "" {
		slog.SetDefault(slog.New(slog.DiscardHandler))
	}
}

// mpathStack is the new stack under the netem harness
type mpathStack struct {
	client, server *Mux
	srv            *Server
	cli            *Client
	accept         chan net.Conn
	cancel         context.CancelFunc
}

func newMpathStack(t testing.TB, paths []*netem.Path, cfg Config) *mpathStack {
	t.Helper()
	key, _, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	srv := NewServer(key, cfg)
	for _, p := range paths {
		go func() { _ = srv.HandleConn(context.Background(), p.B) }()
	}
	cli, err := NewClient(key.PublicKey(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, p := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cli.AddPath(ctx, p.A); err != nil {
				t.Errorf("add path: %v", err)
			}
		}()
	}
	wg.Wait()

	var ss *Session
	select {
	case ss = <-srv.Accept():
	case <-ctx.Done():
		t.Fatal("server session not accepted")
	}
	cm, err := NewClientMux(cli.Session())
	if err != nil {
		t.Fatal(err)
	}
	sm, err := NewServerMux(ss)
	if err != nil {
		t.Fatal(err)
	}
	actx, acancel := context.WithCancel(context.Background())
	st := &mpathStack{client: cm, server: sm, srv: srv, cli: cli, accept: make(chan net.Conn, 64), cancel: acancel}
	go func() {
		for {
			s, err := sm.AcceptStream(actx)
			if err != nil {
				return
			}
			st.accept <- s
		}
	}()
	go func() {
		for {
			f, err := sm.AcceptDatagramFlow(actx)
			if err != nil {
				return
			}
			st.accept <- f
		}
	}()
	return st
}

func (s *mpathStack) OpenStream() (net.Conn, error)   { return s.client.OpenStream(0) }
func (s *mpathStack) OpenDatagram() (net.Conn, error) { return s.client.OpenDatagramFlow(1), nil }
func (s *mpathStack) Accept() <-chan net.Conn         { return s.accept }
func (s *mpathStack) Close() error {
	s.cancel()
	_ = s.client.Close()
	return s.server.Close()
}

func (s *mpathStack) counters() string {
	c, sv := s.client.Session().Stats(), s.server.Session().Stats()
	var lost, sent uint64
	alive := 0
	for _, p := range c.Paths {
		lost += p.PacketsLost
		sent += p.PacketsSent
		if !p.Dead {
			alive++
		}
	}
	return fmt.Sprintf("segs %d  retrans %d (%.1f%%)  spurious %d (%.2f%%)  path-lost %d/%d  alive %d",
		c.SegmentsSent, c.Retransmits, 100*float64(c.Retransmits)/float64(max(c.SegmentsSent, 1)),
		sv.DupSegments, 100*float64(sv.DupSegments)/float64(max(c.SegmentsSent, 1)), lost, sent, alive)
}

func kb(tl []int64) []int64 {
	out := make([]int64, len(tl))
	for i, v := range tl {
		out[i] = v / 1024
	}
	return out
}

func pathDrops(paths []*netem.Path) string {
	var sent, policed uint64
	for _, p := range paths {
		sent += p.StatsAB().Sent.Load() + p.StatsBA().Sent.Load()
		policed += p.StatsAB().Policed.Load() + p.StatsBA().Policed.Load()
	}
	return fmt.Sprintf("policed %.1f%%", 100*float64(policed)/float64(max(sent, 1)))
}

// TestBenchMpath measures the multipath stack on the emulator; enable with NETEM_BENCH=1
func TestBenchMpath(t *testing.T) {
	if os.Getenv("NETEM_BENCH") == "" {
		t.Skip("set NETEM_BENCH=1 to run the emulator benchmark")
	}
	dur, warm := 15*time.Second, 3*time.Second
	only := os.Getenv("NETEM_ONLY")

	run := func(name string, fn func(st *mpathStack, paths []*netem.Path) netem.Result) {
		if only != "" && only != name {
			return
		}
		paths := netem.NewPaths(netem.DefaultMulti(), 1)
		st := newMpathStack(t, paths, Config{})
		res := fn(st, paths)
		res.Name = name
		res.Extra = st.counters() + "  " + pathDrops(paths)
		t.Log(res.String())
		t.Logf("  timeline KB/250ms: %v", kb(res.Timeline))
		if os.Getenv("NETEM_PATHS") != "" {
			for i, p := range st.client.Session().Stats().Paths {
				t.Logf("  path %d: rate %.0fKB/s srtt %v sent %d lost %d acked %dKB dead %v", i, p.PacingRate/1024, p.SmoothedRTT.Round(time.Millisecond), p.PacketsSent, p.PacketsLost, p.BytesAcked/1024, p.Dead)
			}
		}
		_ = st.Close()
		for _, p := range paths {
			p.Close()
		}
	}

	run("tcp1", func(st *mpathStack, _ []*netem.Path) netem.Result {
		return netem.RunStreams("", st, netem.StreamOptions{Streams: 1, Duration: dur, Warmup: warm})
	})
	run("tcp16", func(st *mpathStack, _ []*netem.Path) netem.Result {
		return netem.RunStreams("", st, netem.StreamOptions{Streams: 16, Duration: dur, Warmup: warm})
	})
	run("kill3", func(st *mpathStack, paths []*netem.Path) netem.Result {
		killAt := 8 * time.Second
		killed := false
		res := netem.RunStreams("", st, netem.StreamOptions{Streams: 16, Duration: dur, Warmup: warm, During: func(el time.Duration) {
			if !killed && el >= killAt {
				killed = true
				for _, p := range paths[:3] {
					p.SetDown(true)
				}
			}
		}})
		t.Logf("  recovery to 70%%: %v", netem.RecoveryTime(res.Timeline, killAt, 0.7))
		return res
	})
	run("udp", func(st *mpathStack, _ []*netem.Path) netem.Result {
		return netem.RunDatagrams("", st, netem.DatagramOptions{Rate: 1024 * 1024, Size: 1200, Duration: dur, Warmup: warm})
	})
}

// redialNet emulates the peer layer: a removed path is redialed with backoff on the same slot,
// and redials fail while the whole network is down
type redialNet struct {
	mu    sync.Mutex
	down  bool
	cfg   netem.MultiConfig
	seed  uint64
	slots map[net.Conn]int
	live  map[int]*netem.Path
	srv   *Server
	cli   *Client
	dials int
}

func (n *redialNet) setDown(down bool) {
	n.mu.Lock()
	n.down = down
	for _, p := range n.live {
		p.SetDown(down)
	}
	n.mu.Unlock()
}

func (n *redialNet) slotPath(slot int) *netem.Path {
	n.seed++
	d := n.cfg.MinDelay + (n.cfg.MaxDelay-n.cfg.MinDelay)*time.Duration(slot)/time.Duration(max(n.cfg.Paths-1, 1))
	return netem.NewPath(netem.PathConfig{Rate: n.cfg.Rate, Delay: d, Jitter: n.cfg.Jitter}, n.seed*1000)
}

func (n *redialNet) removed(c net.Conn) {
	n.mu.Lock()
	slot, ok := n.slots[c]
	delete(n.slots, c)
	if ok {
		if old := n.live[slot]; old != nil {
			old.Close()
			delete(n.live, slot)
		}
	}
	n.mu.Unlock()
	if ok {
		go n.redial(slot)
	}
}

func (n *redialNet) redial(slot int) {
	delay := time.Second
	for {
		if n.cli.Session().isClosed() {
			return
		}
		n.mu.Lock()
		down := n.down
		var p *netem.Path
		if !down {
			p = n.slotPath(slot)
			n.dials++
		}
		n.mu.Unlock()
		if p != nil {
			go func() { _ = n.srv.HandleConn(context.Background(), p.B) }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := n.cli.AddPath(ctx, p.A)
			cancel()
			if err == nil {
				n.mu.Lock()
				n.slots[p.A] = slot
				n.live[slot] = p
				n.mu.Unlock()
				return
			}
			p.Close()
		}
		time.Sleep(delay)
		delay = min(delay*2, 10*time.Second)
	}
}

// TestOutageResume blackholes every path for 30 s and checks the session comes back; NETEM_BENCH=1
func TestOutageResume(t *testing.T) {
	if os.Getenv("NETEM_BENCH") == "" {
		t.Skip("set NETEM_BENCH=1 to run the emulator benchmark")
	}
	mc := netem.DefaultMulti()
	paths := netem.NewPaths(mc, 1)
	rn := &redialNet{cfg: mc, seed: 1, slots: map[net.Conn]int{}, live: map[int]*netem.Path{}}
	for i, p := range paths {
		rn.slots[p.A] = i
		rn.live[i] = p
	}
	st := newMpathStack(t, paths, Config{})
	defer st.Close()
	rn.srv, rn.cli = st.srv, st.cli
	st.client.Session().SetPathHandlers(func(c net.Conn) { _ = c.Close() }, rn.removed)

	const bucket = 250 * time.Millisecond
	outageAt, outage := 6*time.Second, 30*time.Second
	var restoredAt time.Duration
	res := netem.RunStreams("outage", st, netem.StreamOptions{Streams: 16, Duration: outageAt + outage + 15*time.Second, Warmup: 3 * time.Second,
		During: func(el time.Duration) {
			switch {
			case el >= outageAt && el < outageAt+outage:
				rn.setDown(true)
			case el >= outageAt+outage && restoredAt == 0:
				restoredAt = el
				rn.setDown(false)
			}
		}})
	t.Log(res.String() + "  " + st.counters())
	t.Logf("  timeline KB/250ms: %v  redials %d", kb(res.Timeline), rn.dials)

	k0, k := int(outageAt/bucket), int(restoredAt/bucket)
	var before int64
	for _, v := range res.Timeline[k0-4 : k0] {
		before += v
	}
	resumed := -1
	for i := k; i+4 <= len(res.Timeline); i++ {
		var sum int64
		for _, v := range res.Timeline[i : i+4] {
			sum += v
		}
		if sum*10 >= before*7 {
			resumed = i - k
			break
		}
	}
	if resumed < 0 {
		t.Fatalf("throughput did not recover after the outage")
	}
	t.Logf("  back to 70%% within %v of restore, stream errors %d", time.Duration(resumed)*bucket, res.Errors)
	if res.Errors > 0 {
		t.Fatalf("stream errors during outage: %d", res.Errors)
	}
}

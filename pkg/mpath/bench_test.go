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
	st := &mpathStack{client: cm, server: sm, accept: make(chan net.Conn, 64), cancel: acancel}
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

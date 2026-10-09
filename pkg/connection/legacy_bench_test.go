package connection

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/theairblow/turnable/pkg/netem"
	"github.com/theairblow/turnable/pkg/transport"
	kcp "github.com/xtaci/kcp-go/v5"
)

const (
	routeStream   byte = 0
	routeDatagram byte = 1
	legacyPerPeer      = 250 * 1024 // BandwidthRelay used by the VK platform
)

// legacyStack is the current relay stack: KCP per flow over tinymux over PeerConn striping
type legacyStack struct {
	cancel context.CancelFunc
	client *TinyMuxClient
	server *TinyMuxServer
	accept chan net.Conn
}

func newLegacyStack(paths []*netem.Path) (*legacyStack, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cp, sp := NewPeerConn(ctx), NewPeerConn(ctx)
	for _, p := range paths {
		_ = cp.AddPeer(OneShotDial(p.A))
		_ = sp.AddPeer(OneShotDial(p.B))
	}

	srvCh := make(chan *TinyMuxServer, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := NewTinyMuxServer(sp)
		if err != nil {
			errCh <- err
			return
		}
		srvCh <- s
	}()

	client, err := NewTinyMuxClient(ctx, cp)
	if err != nil {
		cancel()
		return nil, err
	}
	client.SetRateLimit(legacyPerPeer * float64(len(paths)))

	var server *TinyMuxServer
	select {
	case server = <-srvCh:
	case err := <-errCh:
		cancel()
		return nil, err
	case <-time.After(10 * time.Second):
		cancel()
		return nil, fmt.Errorf("server handshake timeout")
	}
	server.SetRateLimit(legacyPerPeer * float64(len(paths)))

	st := &legacyStack{cancel: cancel, client: client, server: server, accept: make(chan net.Conn, 64)}
	go func() {
		for ch := range server.AcceptChannels(ctx) {
			conn := ch.Conn
			if ch.RouteIdx == routeStream {
				if conn, err = transport.WrapKCP(conn); err != nil {
					continue
				}
			}
			st.accept <- conn
		}
	}()
	return st, nil
}

func (s *legacyStack) OpenStream() (net.Conn, error) {
	c, err := s.client.OpenChannel(routeStream)
	if err != nil {
		return nil, err
	}
	return transport.WrapKCP(c)
}

func (s *legacyStack) OpenDatagram() (net.Conn, error) { return s.client.OpenChannel(routeDatagram) }
func (s *legacyStack) Accept() <-chan net.Conn         { return s.accept }

func (s *legacyStack) Close() error {
	_ = s.client.Close()
	_ = s.server.Close()
	s.cancel()
	return nil
}

func kcpCounters(before *kcp.Snmp) string {
	after := kcp.DefaultSnmp.Copy()
	out := after.OutSegs - before.OutSegs
	re := after.RetransSegs - before.RetransSegs
	fast := after.FastRetransSegs - before.FastRetransSegs
	lost := after.LostSegs - before.LostSegs
	return fmt.Sprintf("kcp out %d  retrans %d (%.1f%%)  fast %d  rto-lost %d", out, re, 100*float64(re)/float64(max(out, 1)), fast, lost)
}

func pathDrops(paths []*netem.Path) string {
	var sent, policed uint64
	for _, p := range paths {
		sent += p.StatsAB().Sent.Load() + p.StatsBA().Sent.Load()
		policed += p.StatsAB().Policed.Load() + p.StatsBA().Policed.Load()
	}
	return fmt.Sprintf("policed %.1f%%", 100*float64(policed)/float64(max(sent, 1)))
}

// TestBenchLegacy measures the legacy stack on the emulator; enable with NETEM_BENCH=1
func TestBenchLegacy(t *testing.T) {
	if os.Getenv("NETEM_BENCH") == "" {
		t.Skip("set NETEM_BENCH=1 to run the emulator benchmark")
	}
	dur := 15 * time.Second
	warm := 3 * time.Second

	run := func(name string, fn func(st *legacyStack, paths []*netem.Path) netem.Result) {
		paths := netem.NewPaths(netem.DefaultMulti(), 1)
		st, err := newLegacyStack(paths)
		if err != nil {
			t.Fatal(err)
		}
		before := kcp.DefaultSnmp.Copy()
		res := fn(st, paths)
		res.Extra = kcpCounters(before) + "  " + pathDrops(paths)
		t.Log(res.String())
		t.Logf("  timeline KB/250ms: %v", kb(res.Timeline))
		_ = st.Close()
		for _, p := range paths {
			p.Close()
		}
	}

	run("legacy tcp x1", func(st *legacyStack, _ []*netem.Path) netem.Result {
		return netem.RunStreams("legacy tcp x1", st, netem.StreamOptions{Streams: 1, Duration: dur, Warmup: warm})
	})
	run("legacy tcp x16", func(st *legacyStack, _ []*netem.Path) netem.Result {
		return netem.RunStreams("legacy tcp x16", st, netem.StreamOptions{Streams: 16, Duration: dur, Warmup: warm})
	})
	run("legacy tcp x16 kill3", func(st *legacyStack, paths []*netem.Path) netem.Result {
		killAt := 8 * time.Second
		killed := false
		res := netem.RunStreams("legacy tcp x16 kill3", st, netem.StreamOptions{Streams: 16, Duration: dur, Warmup: warm, During: func(el time.Duration) {
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
	run("legacy udp 1MB/s", func(st *legacyStack, _ []*netem.Path) netem.Result {
		return netem.RunDatagrams("legacy udp 1MB/s", st, netem.DatagramOptions{Rate: 1024 * 1024, Size: 1200, Duration: dur, Warmup: warm})
	})
}

func kb(tl []int64) []int64 {
	out := make([]int64, len(tl))
	for i, v := range tl {
		out[i] = v / 1024
	}
	return out
}

func init() {
	if os.Getenv("NETEM_BENCH") != "" && os.Getenv("NETEM_LOG") == "" {
		slog.SetDefault(slog.New(slog.DiscardHandler))
	}
}

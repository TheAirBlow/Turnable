package mpath

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBenchMux loads the session the way the app does, bulk and a latency probe on smux streams, one direction at a time
func TestBenchMux(t *testing.T) {
	if os.Getenv("MPATH_BENCH") == "" {
		t.Skip("set MPATH_BENCH=1")
	}
	const capacity = 600 * 1024
	ms := time.Millisecond
	up := &simLink{rate: capacity, owd: 35 * ms, maxQueue: 1500 * ms}
	down := &simLink{rate: capacity, owd: 35 * ms, maxQueue: 1500 * ms}
	if v, _ := strconv.ParseFloat(os.Getenv("LOSS"), 64); v > 0 {
		up.loss, down.loss = v, v
	}
	perPath := os.Getenv("PERPATH") != ""
	var stage func(bool) *simLink
	if perPath {
		stage = func(bool) *simLink { return &simLink{rate: 250 * 1024, maxQueue: 60 * ms} }
	}
	n := newSimNet(t, 8, up, down, Config{}, stage)
	for i, c := range n.cliConns {
		c.extra = time.Duration(i*5) * ms
	}
	for i, c := range n.srvConns {
		c.extra = time.Duration(i*5) * ms
	}
	if amp, _ := time.ParseDuration(os.Getenv("WANDER")); amp > 0 {
		for i, c := range append(slices.Clone(n.cliConns), n.srvConns...) {
			c.wander = wander(uint64(i), amp, 1500*ms)
		}
	}
	cm, err := NewClientMux(n.cli)
	if err != nil {
		t.Fatal(err)
	}
	sm, err := NewServerMux(n.srv)
	if err != nil {
		t.Fatal(err)
	}

	// bulk and probe streams in both directions; dir 0 = client->server
	var bulk [2]atomic.Int64
	var on [2]atomic.Bool
	var lat [2][]time.Duration
	var latMu sync.Mutex
	open := func(a, b *Mux, dir int) {
		go func() {
			for _, probe := range []bool{false, true} {
				st, err := a.OpenStream(byte(dir))
				if err != nil {
					return
				}
				if probe {
					go func() {
						buf := make([]byte, 8)
						for {
							time.Sleep(250 * ms)
							if !on[dir].Load() {
								continue
							}
							binary.BigEndian.PutUint64(buf, uint64(time.Now().UnixNano()))
							if _, err := st.Write(buf); err != nil {
								return
							}
						}
					}()
				} else {
					go func() {
						buf := make([]byte, 32*1024)
						for {
							if !on[dir].Load() {
								time.Sleep(50 * ms)
								continue
							}
							if _, err := st.Write(buf); err != nil {
								return
							}
						}
					}()
				}
			}
		}()
		go func() {
			for i := 0; i < 2; i++ {
				st, err := b.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					if st.Route == 0xFF {
						return
					}
					buf := make([]byte, 64*1024)
					first := true
					_ = first
					for {
						k, err := st.Read(buf)
						if err != nil {
							return
						}
						if k == 8 {
							d := time.Since(time.Unix(0, int64(binary.BigEndian.Uint64(buf))))
							latMu.Lock()
							lat[dir] = append(lat[dir], d)
							latMu.Unlock()
						} else {
							bulk[dir].Add(int64(k))
						}
					}
				}()
			}
		}()
	}
	open(cm, sm, 0)
	open(sm, cm, 1)

	phases := []struct {
		name string
		dir  int
		dur  time.Duration
	}{{"upload", 0, 20 * time.Second}, {"download", 1, 20 * time.Second}}
	for _, ph := range phases {
		on[ph.dir].Store(true)
		latMu.Lock()
		lat[ph.dir] = nil
		latMu.Unlock()
		var last int64 = bulk[ph.dir].Load()
		for s := 1; s <= int(ph.dur.Seconds()); s++ {
			time.Sleep(time.Second)
			g := bulk[ph.dir].Load()
			src := n.cli
			if ph.dir == 1 {
				src = n.srv
			}
			src.mu.Lock()
			fmt.Printf("  %s t=%2ds goodput=%4d KB/s cc.rate=%4.0f q=%3dms sendbuf=%d\n", ph.name, s, (g-last)/1024, src.cc.rate/1024, src.cc.queue.Milliseconds(), src.sendBuffered)
			src.mu.Unlock()
			last = g
		}
		on[ph.dir].Store(false)
		latMu.Lock()
		l := slices.Clone(lat[ph.dir])
		latMu.Unlock()
		slices.Sort(l)
		if len(l) > 0 {
			fmt.Printf("%s: probe one-way latency p50=%v max=%v (n=%d)\n", ph.name, l[len(l)/2], l[len(l)-1], len(l))
		}
		time.Sleep(3 * time.Second)
	}
	_ = io.EOF
}

// wander is a seeded piecewise-linear delay in [0, amp], re-drawn every step
func wander(seed uint64, amp, step time.Duration) func(time.Duration) time.Duration {
	r := rand.New(rand.NewPCG(seed, 7))
	v := make([]float64, 200)
	for i := range v {
		v[i] = r.Float64() * r.Float64()
	}
	return func(t time.Duration) time.Duration {
		f := float64(t) / float64(step)
		i := int(f) % (len(v) - 1)
		fr := f - float64(int(f))
		return time.Duration((v[i]*(1-fr) + v[i+1]*fr) * float64(amp))
	}
}

package mpath

import (
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// capacity profile: bytes/sec at time t
type profile func(t time.Duration) float64

func constant(r float64) profile { return func(time.Duration) float64 { return r } }

func stepped(base float64, steps ...[3]float64) profile { // [from s, to s, rate]
	return func(t time.Duration) float64 {
		for _, s := range steps {
			if t.Seconds() >= s[0] && t.Seconds() < s[1] {
				return s[2]
			}
		}
		return base
	}
}

// walk is a seeded random capacity that changes every step
func walk(seed uint64, lo, hi float64, step time.Duration) profile {
	r := rand.New(rand.NewPCG(seed, 1))
	vals := make([]float64, 400)
	cur := math.Sqrt(lo * hi)
	for i := range vals {
		cur *= math.Exp(r.NormFloat64() * 0.45)
		cur = math.Min(math.Max(cur, lo), hi)
		vals[i] = cur
	}
	return func(t time.Duration) float64 { return vals[int(t/step)%len(vals)] }
}

// episodes returns radio-state delay inflation: add for len out of every period, seeded
func episodes(seed uint64, add time.Duration, period, length time.Duration) func(time.Duration) time.Duration {
	r := rand.New(rand.NewPCG(seed, 2))
	starts := make([]time.Duration, 200)
	cur := period / 2
	for i := range starts {
		cur += time.Duration(float64(period) * (0.5 + r.Float64()))
		starts[i] = cur
	}
	return func(t time.Duration) time.Duration {
		for _, s := range starts {
			if t >= s && t < s+length {
				return add
			}
		}
		return 0
	}
}

type benchCase struct {
	name    string
	prof    profile
	extra   func(time.Duration) time.Duration
	owd     time.Duration
	queue   time.Duration
	paths   int
	perPath float64 // per-path policer rate, 0 for none
	bidir   bool    // load the return direction too, at the same capacity
}

func runBench(t *testing.T, c benchCase, dur time.Duration, trace bool) (ratio float64, p50, p95 time.Duration) {
	up := &simLink{rate: c.prof(0), owd: c.owd, maxQueue: c.queue, extra: c.extra}
	down := &simLink{rate: 2000 * 1024, owd: c.owd, maxQueue: c.queue}
	if c.bidir {
		down.rate = c.prof(0)
	}
	var stage func(bool) *simLink
	if c.perPath > 0 {
		stage = func(bool) *simLink {
			return &simLink{rate: c.perPath, maxQueue: 60 * time.Millisecond}
		}
	}
	n := newSimNet(t, c.paths, up, down, Config{}, stage)
	got := pump(n.cli, n.srv)
	var got2 = new(atomic.Int64)
	if c.bidir {
		got2 = pump(n.srv, n.cli)
	}
	start := time.Now()
	var capInt float64
	var last int64
	lastT := time.Duration(0)
	for el := 100 * time.Millisecond; el <= dur; el += 100 * time.Millisecond {
		time.Sleep(time.Until(start.Add(el)))
		r := c.prof(el)
		up.setRate(r)
		if c.bidir {
			down.setRate(r)
		}
		capInt += r * 0.1
		if trace && el%time.Second == 0 {
			g := got.Load()
			n.cli.mu.Lock()
			fmt.Printf("  t=%2ds cap=%4.0f goodput=%4d cc.rate=%4.0f q=%3dms\n", int(el.Seconds()), r/1024, (g-last)/1024, n.cli.cc.rate/1024, n.cli.cc.queue.Milliseconds())
			n.cli.mu.Unlock()
			last, lastT = g, el
		}
	}
	_ = lastT
	if c.bidir {
		fmt.Printf("  reverse goodput/capacity = %.2f\n", float64(got2.Load())/capInt)
	}
	return float64(got.Load()) / capInt, up.queuePct(0.5), up.queuePct(0.95)
}

func benchCases() []benchCase {
	ms := time.Millisecond
	return []benchCase{
		{"steady-bloat", constant(400 * 1024), nil, 45 * ms, 1500 * ms, 4, 0, false},
		{"lte-walk", walk(1, 120*1024, 700*1024, time.Second), nil, 45 * ms, 1500 * ms, 4, 0, false},
		{"lte-walk+radio", walk(2, 120*1024, 700*1024, time.Second), episodes(3, 250*ms, 8*time.Second, 2*time.Second), 45 * ms, 1500 * ms, 4, 0, false},
		{"steady+radio", constant(400 * 1024), episodes(4, 250*ms, 8*time.Second, 2*time.Second), 45 * ms, 1500 * ms, 4, 0, false},
		{"dip", stepped(400*1024, [3]float64{8, 12, 100 * 1024}), nil, 45 * ms, 1500 * ms, 4, 0, false},
		{"persist", constant(400 * 1024), func(t time.Duration) time.Duration {
			if t > 8*time.Second {
				return 250 * ms
			}
			return 0
		}, 45 * ms, 1500 * ms, 4, 0, false},
		{"turn-lte-steady", constant(1000 * 1024), nil, 45 * ms, 1500 * ms, 8, 250 * 1024, false},
		{"turn-path-limited", constant(3000 * 1024), nil, 45 * ms, 1500 * ms, 6, 100 * 1024, false},
		{"turn-walk", walk(5, 150*1024, 1200*1024, time.Second), nil, 45 * ms, 1500 * ms, 8, 200 * 1024, false},
		{"turn-walk+radio", walk(6, 150*1024, 1200*1024, time.Second), episodes(7, 250*ms, 8*time.Second, 2*time.Second), 45 * ms, 1500 * ms, 8, 200 * 1024, false},
		{"persist400", constant(400 * 1024), func(t time.Duration) time.Duration {
			if t > 8*time.Second {
				return 400 * ms
			}
			return 0
		}, 45 * ms, 1500 * ms, 4, 0, false},
		{"radio400", constant(400 * 1024), episodes(8, 400*ms, 6*time.Second, 3*time.Second), 45 * ms, 1500 * ms, 4, 0, false},
		{"turn-walk+radio400", walk(6, 150*1024, 1200*1024, time.Second), episodes(7, 400*ms, 6*time.Second, 3*time.Second), 45 * ms, 1500 * ms, 8, 200 * 1024, false},
		{"highrtt-steady", constant(400 * 1024), nil, 150 * ms, 1500 * ms, 4, 0, false},
		{"highrtt-walk", walk(9, 120*1024, 700*1024, time.Second), nil, 150 * ms, 1500 * ms, 4, 0, false},
		{"bidir-600", constant(600 * 1024), nil, 45 * ms, 1500 * ms, 8, 250 * 1024, true},
		{"bidir-600-nopath", constant(600 * 1024), nil, 45 * ms, 1500 * ms, 8, 0, true},
		{"slow-lte", constant(60 * 1024), nil, 45 * ms, 1500 * ms, 4, 0, false},
	}
}

func TestBench(t *testing.T) {
	if os.Getenv("MPATH_BENCH") == "" {
		t.Skip("set MPATH_BENCH=1 to run the link emulator benchmark; CASE selects one, TRACE=1 prints each second")
	}
	only := os.Getenv("CASE")
	for _, c := range benchCases() {
		if only != "" && only != c.name {
			continue
		}
		r, p50, p95 := runBench(t, c, 40*time.Second, os.Getenv("TRACE") != "")
		fmt.Printf("%-18s goodput/capacity = %.2f  queue p50=%4dms p95=%4dms\n", c.name, r, p50.Milliseconds(), p95.Milliseconds())
	}
}

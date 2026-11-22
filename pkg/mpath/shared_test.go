package mpath

import (
	"testing"
	"time"
)

// fluidLink is a bottleneck with a drop-tail queue and a delay-line of ACKs, stepped in virtual time
type fluidLink struct {
	cap      func(t time.Duration) float64       // bytes/sec
	extra    func(t time.Duration) time.Duration // delay the link adds that is not queueing
	base     time.Duration                       // queue-free RTT
	maxQueue float64                             // bytes the queue holds before dropping
	queue    float64
	acks     []rateSample // bytes due back at a time
}

// runShared drives a backlogged sender through c over the link and returns the pacing rate at each second
func runShared(c *shared, l *fluidLink, t0 time.Time, dur time.Duration) []float64 {
	const dt = 5 * time.Millisecond
	var out []float64
	for el := dt; el <= dur; el += dt {
		now := t0.Add(el)
		c.onSend(now, int(c.rate*dt.Seconds()), time.Millisecond)
		l.queue += c.rate * dt.Seconds()
		served := min(l.queue, l.cap(el)*dt.Seconds())
		l.queue -= served
		if l.queue > l.maxQueue {
			l.queue = l.maxQueue
		}
		extra := time.Duration(0)
		if l.extra != nil {
			extra = l.extra(el)
		}
		l.acks = append(l.acks, rateSample{now.Add(l.base + extra), int(served)})
		for len(l.acks) > 0 && !l.acks[0].at.After(now) {
			c.onAcked(l.acks[0].bytes)
			l.acks = l.acks[1:]
		}
		q := time.Duration(l.queue/l.cap(el)*float64(time.Second)) + extra
		c.tick(now, q, l.base, 0)
		if el%time.Second == 0 {
			out = append(out, c.rate)
		}
	}
	return out
}

// newFluid returns a link of fixed capacity with LTE-like buffering
func newFluid(capacity float64, extra func(time.Duration) time.Duration) *fluidLink {
	return &fluidLink{
		cap:      func(time.Duration) float64 { return capacity },
		extra:    extra,
		base:     90 * time.Millisecond,
		maxQueue: capacity * 1.5,
	}
}

func inflation(from, to, add time.Duration) func(time.Duration) time.Duration {
	return func(t time.Duration) time.Duration {
		if t >= from && t < to {
			return add
		}
		return 0
	}
}

func requireRateNear(t *testing.T, rates []float64, sec int, capacity, lo, hi float64) {
	t.Helper()
	if r := rates[sec-1] / capacity; r < lo || r > hi {
		t.Fatalf("t=%ds: pacing rate %.0f KB/s is %.2f of capacity %.0f KB/s, want %.2f..%.2f (KB/s by second: %v)", sec, rates[sec-1]/1024, r, capacity/1024, lo, hi, kb(rates))
	}
}

func kb(r []float64) []int {
	out := make([]int, len(r))
	for i, v := range r {
		out[i] = int(v / 1024)
	}
	return out
}

func TestSharedTracksCapacity(t *testing.T) {
	const capacity = 400 * 1024
	t0 := time.Now()
	rates := runShared(newShared(t0), newFluid(capacity, nil), t0, 20*time.Second)
	requireRateNear(t, rates, 20, capacity, 0.8, 1.4)
}

func TestSharedRecoversFromDelaySpike(t *testing.T) {
	const capacity = 400 * 1024
	t0 := time.Now()
	l := newFluid(capacity, inflation(8*time.Second, 11*time.Second, 250*time.Millisecond))
	rates := runShared(newShared(t0), l, t0, 25*time.Second)
	requireRateNear(t, rates, 25, capacity, 0.85, 1.4)
}

func TestSharedKeepsRateUnderPersistentInflation(t *testing.T) {
	const capacity = 400 * 1024
	t0 := time.Now()
	l := newFluid(capacity, inflation(5*time.Second, time.Hour, 250*time.Millisecond))
	rates := runShared(newShared(t0), l, t0, 30*time.Second)
	requireRateNear(t, rates, 30, capacity, 0.7, 1.4)
}

func TestSharedRecoversFromCapacityDip(t *testing.T) {
	const capacity = 400 * 1024
	t0 := time.Now()
	l := newFluid(capacity, nil)
	l.cap = func(t time.Duration) float64 {
		if t >= 8*time.Second && t < 12*time.Second {
			return capacity / 4
		}
		return capacity
	}
	rates := runShared(newShared(t0), l, t0, 20*time.Second)
	requireRateNear(t, rates, 20, capacity, 0.85, 1.4)
}

func TestSharedFollowsCapacityUp(t *testing.T) {
	t0 := time.Now()
	l := newFluid(100*1024, nil)
	l.cap = func(t time.Duration) float64 {
		if t >= 6*time.Second {
			return 800 * 1024
		}
		return 100 * 1024
	}
	rates := runShared(newShared(t0), l, t0, 16*time.Second)
	requireRateNear(t, rates, 16, 800*1024, 0.8, 1.4)
}

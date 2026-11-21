package mpath

import "time"

const (
	sharedStartRate = 256 * 1024 // session pacing rate before any delivery samples, bytes/sec
	sharedMinRate   = 32 * 1024  // session pacing floor, bytes/sec
	sharedMinWindow = 100 * time.Millisecond
	sharedTargetMin = 100 * time.Millisecond // queue delay tolerated before draining, never below this
	sharedTargetMax = 200 * time.Millisecond // nor above this
	sharedMinSample = 3000                   // bytes committed in an interval below which it says nothing (keepalives, a trickle)
	sharedRateSpan  = 400 * time.Millisecond // delivery is averaged over this long, so ACK bursts do not read as bandwidth
	sharedBwWindow  = 8 * time.Second        // how long a delivery-rate maximum is remembered
	sharedStartup   = 1.5                    // per-interval growth before the bandwidth estimate stops rising
	sharedProbeGain = 1.25                   // pacing gain of a probe interval
	sharedDrainGain = 0.75                   // pacing gain of a drain interval
	sharedProbeEach = 4                      // intervals between probes
	sharedCooldown  = 3                      // cruise intervals after a drain
	sharedStale     = 3                      // intervals of queue well above target before the bandwidth estimate is cut
)

// rateSample is the bytes acknowledged in one measurement interval
type rateSample struct {
	at    time.Time
	bytes int
}

// maxSample is a delivery rate measured at a time
type maxSample struct {
	at   time.Time
	rate float64
}

// shared paces the whole session against the bottleneck its paths have in common: it holds the best recent delivery rate and paces around it, draining whenever a standing queue shows up, so jitter and random loss never shrink the rate on their own
type shared struct {
	rate    float64       // session pacing rate, bytes/sec
	next    time.Time     // when the next packet may leave
	startup bool          // the bandwidth estimate is still rising
	ivStart time.Time     // start of the current measurement interval
	ivAcked int           // bytes acknowledged this interval
	ivSent  int           // bytes committed this interval
	hist    []rateSample  // recent intervals, for the delivery rate over sharedRateSpan
	peaks   []maxSample   // decreasing delivery rates, front is the maximum over sharedBwWindow
	queue   time.Duration // standing queue delay measured in the last interval
	cycle   int           // intervals since the last probe
	drain   bool          // the next interval drains a queue
	cool    int           // intervals before another drain may start; the delay may be jitter, which a lower rate cannot cure
	high    int           // consecutive intervals with the queue far above target
	probing bool          // the last interval paced above the estimate to look for room
	probeBw float64       // bandwidth estimate when that probe began
}

// newShared returns a controller that probes upward from the start rate
func newShared(now time.Time) *shared {
	return &shared{rate: sharedStartRate, next: now, startup: true, ivStart: now}
}

// backlog is how far the session pacer is booked ahead of now
func (c *shared) backlog(now time.Time) time.Duration { return c.next.Sub(now) }

// onSend books size bytes on the session pacer
func (c *shared) onSend(now time.Time, size int, burst time.Duration) {
	ns := c.next
	if floor := now.Add(-burst); ns.Before(floor) {
		ns = floor
	}
	c.next = ns.Add(time.Duration(float64(size) / c.rate * float64(time.Second)))
	c.ivSent += size
}

// onAcked counts newly delivered bytes
func (c *shared) onAcked(n int) { c.ivAcked += n }

// addPeak records a delivery rate in the windowed maximum
func (c *shared) addPeak(now time.Time, r float64) {
	for len(c.peaks) > 0 && c.peaks[len(c.peaks)-1].rate <= r {
		c.peaks = c.peaks[:len(c.peaks)-1]
	}
	c.peaks = append(c.peaks, maxSample{now, r})
}

// bandwidth returns the largest delivery rate within the window
func (c *shared) bandwidth(now time.Time) float64 {
	for len(c.peaks) > 1 && now.Sub(c.peaks[0].at) > sharedBwWindow {
		c.peaks = c.peaks[1:]
	}
	if len(c.peaks) == 0 {
		return 0
	}
	return c.peaks[0].rate
}

// tick closes the measurement interval once it is long enough; q is the median per-path standing queue delay seen, base the typical queue-free RTT
func (c *shared) tick(now time.Time, q, base time.Duration, maxRate float64) {
	iv := max(base, sharedMinWindow)
	el := now.Sub(c.ivStart)
	if el < iv {
		return
	}
	acked, sent := c.ivAcked, c.ivSent
	c.ivStart, c.ivAcked, c.ivSent = now, 0, 0
	if acked == 0 || sent < sharedMinSample {
		return // idle or stalled: keep the rate, nothing was learned
	}
	c.hist = append(c.hist, rateSample{now, acked})
	for len(c.hist) > 1 && now.Sub(c.hist[0].at) > sharedRateSpan+iv {
		c.hist = c.hist[1:]
	}
	if span := now.Sub(c.hist[0].at) + iv; span >= sharedRateSpan {
		var sum int
		for _, h := range c.hist {
			sum += h.bytes
		}
		c.addPeak(now, float64(sum)/span.Seconds())
	}
	c.queue = q
	bw := c.bandwidth(now)
	target := min(max(base, sharedTargetMin), sharedTargetMax)
	used := float64(sent) >= 0.8*c.rate*el.Seconds()

	if q > 2*target {
		c.high++
	} else {
		c.high = 0
	}
	if c.high >= sharedStale {
		// the queue will not drain at this estimate: it is stale or inflated by ACK bursts
		c.peaks = c.peaks[:0]
		bw = 0.85 * c.rate
		c.addPeak(now, bw)
		c.high, c.startup = 0, false
	}

	if c.startup {
		if q <= target && c.rate < maxRateOr(maxRate) {
			if used {
				c.rate *= sharedStartup
			}
			c.finish(maxRate)
			return
		}
		c.startup, c.drain = false, true
	}

	if c.probing {
		c.probing = false
		if bw > c.probeBw*1.05 && q <= target {
			c.cycle = sharedProbeEach // the probe found room: probe again at once
		} else {
			c.drain = true // drain the queue the probe may have built
		}
	}
	if c.cool > 0 {
		c.cool--
	} else if q > target {
		c.drain = true
	}
	gain := 1.0
	switch {
	case c.drain:
		gain, c.drain, c.cycle, c.cool = sharedDrainGain, false, 0, sharedCooldown
	case c.cycle >= sharedProbeEach && used && q < target/2:
		gain, c.cycle, c.probing, c.probeBw = sharedProbeGain, 0, true, bw
	default:
		c.cycle++
	}
	c.rate = max(bw*gain, sharedMinRate)
	c.finish(maxRate)
}

// finish applies the configured ceiling
func (c *shared) finish(maxRate float64) {
	if maxRate > 0 && c.rate > maxRate {
		c.rate = maxRate
	}
}

// maxRateOr returns the ceiling, or infinity when none is set
func maxRateOr(maxRate float64) float64 {
	if maxRate > 0 {
		return maxRate
	}
	return 1e18
}

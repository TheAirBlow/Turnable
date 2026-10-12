package mpath

import (
	mrand "math/rand/v2"
	"net"
	"sync"
	"time"
)

// sentPkt is one ack-eliciting packet in flight on a path
type sentPkt struct {
	seq           uint32    // path sequence number
	sendTime      time.Time // when the packet leaves (its pacing time)
	size          int       // bytes on the wire
	seg           *segment  // reliable segment carried, nil for datagrams and pings
	delivered     uint64    // path delivered bytes when this packet was sent
	deliveredTime time.Time // when delivered was last advanced at send time
	firstSent     time.Time // send time of the newest packet acked when this one was sent
	appLimited    bool      // sent while the session had nothing more queued
	lost          bool      // declared lost by timeout; kept so a late ACK still proves liveness
}

// queued is a packet committed to a path, written once its pacing time arrives
type queued struct {
	due   time.Time // pacing time at which to write the packet
	plain []byte    // plaintext, sealed when written
}

// bwFilter is a windowed max of delivery-rate samples
type bwFilter struct {
	buckets [bwBuckets]float64 // max sample per bucket
	stamp   [bwBuckets]int64   // bucket number each slot was last written for
}

const (
	lostRetention  = 3 * time.Second        // how long timed-out packets are remembered for late ACKs
	bwBuckets      = 20                     // buckets in the bandwidth filter window
	bwBucketPeriod = 100 * time.Millisecond // bucket length, for a 2 s window
)

// add records a delivery-rate sample
func (f *bwFilter) add(now time.Time, v float64) {
	b := now.UnixNano() / int64(bwBucketPeriod)
	i := b % bwBuckets
	if f.stamp[i] != b {
		f.stamp[i], f.buckets[i] = b, 0
	}
	if v > f.buckets[i] {
		f.buckets[i] = v
	}
}

// max returns the largest sample in the window
func (f *bwFilter) max(now time.Time) float64 {
	b := now.UnixNano() / int64(bwBucketPeriod)
	m := 0.0
	for i := range f.buckets {
		if b-f.stamp[i] < bwBuckets && f.buckets[i] > m {
			m = f.buckets[i]
		}
	}
	return m
}

// reset clears the filter and seeds it with v
func (f *bwFilter) reset(now time.Time, v float64) {
	*f = bwFilter{}
	f.add(now, v)
}

// gainCycle is the pacing gain per round: a short probe up, a drain, then cruise just under the cap
var gainCycle = [...]float64{1.05, 0.9, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97, 0.97}

// path is one peer connection carrying a share of the session
type path struct {
	id      int        // local path index, for logs
	conn    net.Conn   // peer connection
	writeMu sync.Mutex // serializes writes to conn
	cfg     *Config    // session tuning

	// lifecycle, guarded by Session.mu
	dead      bool
	removed   bool      // conn failed or expired; no longer in the session
	deadSince time.Time // when the path was declared dead

	// sender state
	outq          []queued   // paced packets waiting for their send time
	nextSeq       uint32     // next path sequence number
	sent          []*sentPkt // ack-eliciting packets awaiting an ACK, in send order
	inflight      int        // bytes in flight
	nextSendTime  time.Time  // pacer: when the next packet may leave
	waitingSince  time.Time  // first ack-eliciting send not yet followed by an ack
	lastAckTime   time.Time  // last ACK that acknowledged something new
	lastEliciting time.Time  // last ack-eliciting send, for keepalives
	lastProbe     time.Time  // last probe sent on a dead path

	srtt            time.Duration // smoothed RTT
	rttvar          time.Duration // RTT variation
	minRTT          time.Duration // lowest RTT in the last two windows, the queue-free baseline
	minCur, minPrev time.Duration // lowest RTT in the current and previous window
	minRotate       time.Time     // when the current window ends
	hasRTT          bool          // srtt holds a real sample

	bw             bwFilter  // windowed max delivery rate
	ceiling        float64   // loss-derived rate cap, 0 for none
	capFound       bool      // a policer has been hit at least once
	demand         bool      // the session has more to send than the paths take; probing only then
	delivered      uint64    // bytes acknowledged so far
	deliveredTime  time.Time // when delivered last advanced
	firstSent      time.Time // send time of the newest acknowledged packet
	gainIdx        int       // position in gainCycle
	gainStart      time.Time // start of the current gain phase
	delayStart     time.Time // start of the current delay-control interval
	delayDelivered uint64    // delivered bytes at delayStart
	epochStart     time.Time // start of the current loss epoch
	epochSent      int       // packets
	epochLost      int       // packets lost this epoch
	epochBytes     int       // bytes sent
	epochAcked     int       // bytes acked

	// receiver state
	recvLargest  uint32
	recvAny      bool      // false until the first packet
	recvBitmap   uint64    // which of the 64 sequences below recvLargest arrived
	ackPending   int       // ack-eliciting packets received since the last ACK
	ackFirstTime time.Time // when the oldest unacknowledged packet arrived

	stats PathStats // counters
}

// PathStats are per-path counters
type PathStats struct {
	PacketsSent  uint64        // ack-eliciting packets sent
	PacketsLost  uint64        // packets declared lost
	BytesSent    uint64        // bytes sent
	BytesAcked   uint64        // bytes acknowledged
	PacingRate   float64       // current pacing rate, bytes/sec
	SmoothedRTT  time.Duration // smoothed RTT
	Dead         bool          // the path is dead
	PacketsRecvd uint64        // packets received
	MinRTT       time.Duration // lowest RTT seen
	Inflight     int           // bytes in flight
	Ceiling      float64       // loss-derived rate cap, 0 for none
}

// newPath creates the state for a newly attached peer conn
func newPath(id int, conn net.Conn, cfg *Config, now time.Time) *path {
	return &path{
		id: id, conn: conn, cfg: cfg,
		nextSeq:       initialPathSeq(),
		lastAckTime:   now,
		deliveredTime: now,
		gainStart:     now,
		epochStart:    now,
		nextSendTime:  now,
	}
}

// initialPathSeq picks a random starting sequence; serial arithmetic handles the wrap
func initialPathSeq() uint32 { return mrand.Uint32() }

// rtt returns the smoothed RTT or a conservative default
func (p *path) rtt() time.Duration {
	if !p.hasRTT {
		return p.cfg.InitialRTT
	}
	return p.srtt
}

// rate returns the current pacing rate in bytes/sec
func (p *path) rate(now time.Time) float64 {
	// app-limited samples are tiny, so only measured loss (the ceiling) may pace below the initial rate
	bw := max(p.bw.max(now), p.cfg.InitialRate)
	gain := gainCycle[p.gainIdx]
	if !p.demand {
		gain = 1 // nothing is waiting: no probing (it only risks loss) and no cruise margin needed
	} else if p.gainIdx == 0 && p.ceiling == 0 && !p.capFound {
		gain = 1.25 // no cap seen yet: probe hard so unthrottled headroom is found quickly
	}
	r := bw * gain
	if p.ceiling > 0 && r > p.ceiling {
		r = p.ceiling
	}
	floor := p.cfg.MinRate
	if p.ceiling > 0 {
		floor = min(floor, p.ceiling) // a delay cap may sit below the floor: the paths share one link, and 10 floors can exceed it
	}
	if r < floor {
		r = floor
	}
	if p.cfg.MaxRate > 0 && r > p.cfg.MaxRate {
		r = p.cfg.MaxRate
	}
	return r
}

// probing reports whether the pacer is in its probe-up phase, where a policer may drop packets
func (p *path) probing() bool { return p.demand && gainCycle[p.gainIdx] > 1 }

// cwnd caps bytes in flight so a stalled path cannot swallow unbounded data
func (p *path) cwnd(now time.Time) int {
	// sized from the minimum RTT: srtt includes our own queueing, so using it would let the window grow with the queue
	base := p.minRTT
	if base == 0 {
		base = p.rtt()
	}
	// the rttvar term absorbs ACK bursts on jittery links
	bdp := p.rate(now) * (base + 4*p.rttvar).Seconds()
	return max(int(2*bdp), 12*p.cfg.MaxPacketSize)
}

// canSend reports whether the path may take a packet now or soon
func (p *path) usable(now time.Time) bool {
	return !p.dead && !p.removed && p.inflight+p.cfg.MaxPacketSize <= p.cwnd(now)
}

// arrival estimates when a packet handed to this path now would reach the peer
func (p *path) arrival(now time.Time) time.Time {
	t := p.nextSendTime
	if t.Before(now) {
		t = now
	}
	return t.Add(p.owd())
}

// owd estimates the one-way delay from the minimum RTT, which excludes queueing noise
func (p *path) owd() time.Duration {
	if p.minRTT > 0 {
		return p.minRTT / 2
	}
	return p.rtt() / 2
}

// onSend records an ack-eliciting packet, advances the pacer and returns its sequence and send time
func (p *path) onSend(now time.Time, size int, seg *segment, appLimited bool, paced bool) (uint32, time.Time) {
	seq := p.nextSeq
	p.nextSeq++
	due := now
	if paced {
		// allow a small burst credit so timer granularity does not cost throughput
		ns := p.nextSendTime
		if floor := now.Add(-p.cfg.PacingBurst); ns.Before(floor) {
			ns = floor
		}
		if ns.After(now) {
			due = ns
		}
		p.nextSendTime = ns.Add(time.Duration(float64(size) / p.rate(now) * float64(time.Second)))
	}
	if p.inflight == 0 {
		// restart delivery-rate accounting after idle so the gap does not depress samples
		p.deliveredTime, p.firstSent = now, due
	}
	p.sent = append(p.sent, &sentPkt{seq: seq, sendTime: due, size: size, seg: seg, delivered: p.delivered, deliveredTime: p.deliveredTime, firstSent: p.firstSent, appLimited: appLimited})
	p.inflight += size
	if p.waitingSince.IsZero() {
		p.waitingSince = now
	}
	p.lastEliciting = now
	p.epochSent++
	p.epochBytes += size
	p.stats.PacketsSent++
	p.stats.BytesSent += uint64(size)
	return seq, due
}

// backlog is how far the pacer is booked ahead of now
func (p *path) backlog(now time.Time) time.Duration {
	return p.nextSendTime.Sub(now)
}

// onAck processes an ACK and returns the packets declared lost
func (p *path) onAck(now time.Time, largest uint32, delay time.Duration, bitmap uint64) (lost []*sentPkt, acked []*segment, newlyAcked int) {
	isAcked := func(seq uint32) bool {
		if seq == largest {
			return true
		}
		d := int32(largest - seq) // serial arithmetic: path sequences may wrap
		if d < 0 {
			return false
		}
		return d <= 64 && bitmap&(1<<(d-1)) != 0
	}

	var bestSample float64
	sampleValid := false
	kept := p.sent[:0]
	for _, sp := range p.sent {
		if sp.lost {
			switch {
			case isAcked(sp.seq):
				// late ACK after a timeout: the path is alive, the requeue was spurious
				newlyAcked++
				if sp.seq == largest {
					p.updateRTT(now.Sub(sp.sendTime), delay)
				}
			case now.Sub(sp.sendTime) < lostRetention:
				kept = append(kept, sp)
			}
			continue
		}
		switch {
		case isAcked(sp.seq):
			newlyAcked++
			p.inflight -= sp.size
			p.delivered += uint64(sp.size)
			p.deliveredTime = now
			p.stats.BytesAcked += uint64(sp.size)
			p.epochAcked += sp.size
			if sp.seg != nil {
				acked = append(acked, sp.seg)
			}
			if sp.seq == largest {
				p.updateRTT(now.Sub(sp.sendTime), delay)
			}
			p.firstSent = sp.sendTime
			// the slower of the send and ACK intervals, so a policer's burst allowance cannot inflate the sample
			el := max(now.Sub(sp.deliveredTime), sp.sendTime.Sub(sp.firstSent))
			if el > 0 {
				s := float64(p.delivered-sp.delivered) / el.Seconds()
				if s > bestSample && (!sp.appLimited || s > p.bw.max(now)) {
					bestSample, sampleValid = s, true
				}
			}
		case int32(largest-sp.seq) > 0 && (int32(largest-sp.seq) >= 3 || now.Sub(sp.sendTime) > p.lossDelay()):
			lost = append(lost, sp)
			p.inflight -= sp.size
		default:
			kept = append(kept, sp)
		}
	}
	clear(p.sent[len(kept):])
	p.sent = kept
	if newlyAcked == 0 && len(lost) == 0 {
		return nil, nil, 0
	}

	if newlyAcked > 0 {
		p.lastAckTime = now
		if p.inflight <= 0 {
			p.waitingSince = time.Time{}
		} else {
			p.waitingSince = now
		}
	}
	if sampleValid {
		p.bw.add(now, bestSample)
	}
	p.onLoss(len(lost))
	p.advanceCycle(now)
	return lost, acked, newlyAcked
}

// lossDelay is how old an unacknowledged packet must be, with a later one acked, to be declared lost
// it allows for RTT jitter, so a delayed packet on a mobile link is not resent and counted as lost
func (p *path) lossDelay() time.Duration {
	rtt := p.rtt()
	return rtt + max(rtt/8, 2*p.rttvar) + p.cfg.MaxAckDelay
}

// onLoss counts lost packets toward the current epoch
func (p *path) onLoss(n int) {
	p.epochLost += n
	p.stats.PacketsLost += uint64(n)
}

// updateRTT feeds an RTT sample, minus the peer's ACK delay when plausible, into the estimators
func (p *path) updateRTT(sample, delay time.Duration) {
	if sample <= 0 {
		return
	}
	p.noteMinRTT(sample)
	if sample-delay >= p.minRTT {
		sample -= delay
	}
	if !p.hasRTT {
		p.srtt, p.rttvar, p.hasRTT = sample, sample/2, true
		return
	}
	d := p.srtt - sample
	if d < 0 {
		d = -d
	}
	p.rttvar = (3*p.rttvar + d) / 4
	p.srtt = (7*p.srtt + sample) / 8
}

// minRTTWindow is the length of one min-RTT window; the baseline spans two so stale lows age out
const minRTTWindow = 5 * time.Second

// noteMinRTT feeds the windowed minimum that approximates the queue-free RTT
func (p *path) noteMinRTT(sample time.Duration) {
	now := time.Now()
	if p.minRotate.IsZero() {
		p.minRotate = now.Add(minRTTWindow)
	} else if now.After(p.minRotate) {
		p.minPrev, p.minCur = p.minCur, 0
		p.minRotate = now.Add(minRTTWindow)
	}
	if p.minCur == 0 || sample < p.minCur {
		p.minCur = sample
	}
	p.minRTT = p.minCur
	if p.minPrev > 0 && p.minPrev < p.minRTT {
		p.minRTT = p.minPrev
	}
}

// queueDelayed reports whether the smoothed RTT sits above the baseline by more than the target and the jitter
func (p *path) queueDelayed() bool {
	return p.hasRTT && p.minRTT > 0 && p.srtt-p.minRTT > max(p.cfg.DelayTarget, p.minRTT/2, 4*p.rttvar)
}

// delayControl keeps the standing queue short: while the RTT sits above the baseline the path is capped just under its recent delivery rate, and the cap relaxes once the queue drains
// the paths share one bottleneck and each carries little of the load, so this must not wait for per-path packet counts
func (p *path) delayControl(now time.Time) {
	if p.delayStart.IsZero() {
		p.delayStart, p.delayDelivered = now, p.delivered
		return
	}
	el := now.Sub(p.delayStart)
	if el < max(2*p.rtt(), 250*time.Millisecond) {
		return
	}
	got := float64(p.delivered-p.delayDelivered) / el.Seconds()
	p.delayStart, p.delayDelivered = now, p.delivered
	switch {
	case p.queueDelayed():
		if got > 0 {
			// only a real drop lowers an existing cap, otherwise it ratchets down on its own delivery rate
			if c := max(0.9*max(got, p.bw.max(now)), p.cfg.MinRate/4); p.ceiling == 0 || c < 0.7*p.ceiling {
				p.ceiling = c
				p.bw.reset(now, c)
			}
		}
	case p.ceiling > 0:
		p.ceiling *= 1.15
		if p.ceiling > 4*max(p.bw.max(now), p.cfg.InitialRate) {
			p.ceiling = 0
		}
	}
}

// advanceCycle cycles the pacing gain each round trip and reacts to loss once per epoch
func (p *path) advanceCycle(now time.Time) {
	p.delayControl(now)
	round := max(p.rtt(), p.cfg.MinRound)
	if !now.Before(p.gainStart.Add(round)) {
		p.gainIdx = (p.gainIdx + 1) % len(gainCycle)
		p.gainStart = now
	}

	el := now.Sub(p.epochStart)
	if el < max(p.cfg.LossEpoch, 2*p.rtt()) || p.epochSent < 30 {
		return
	}
	lossRate := float64(p.epochLost) / float64(p.epochSent)
	sentRate := float64(p.epochBytes) / el.Seconds()
	deliveryRate := float64(p.epochAcked) / el.Seconds()
	switch {
	case lossRate > p.cfg.LossThreshold && sentRate > 0.5*p.rate(now):
		// a policer is dropping us while we were actually pushing: cap just under what got through
		p.ceiling = max(min(deliveryRate, sentRate*(1-lossRate))*0.95, p.cfg.MinRate)
		p.capFound = true
		p.bw.reset(now, p.ceiling)
	case p.ceiling > 0 && lossRate < p.cfg.LossThreshold/2:
		p.ceiling *= 1.15 // creep back up so a lifted throttle is rediscovered
		if p.ceiling > 4*max(p.bw.max(now), p.cfg.InitialRate) {
			p.ceiling = 0
		}
	}
	p.epochStart, p.epochSent, p.epochLost, p.epochBytes, p.epochAcked = now, 0, 0, 0, 0
}

// takeTimedOut removes packets past the probe timeout, as on a tail loss with no later ACK
func (p *path) takeTimedOut(now time.Time) []*sentPkt {
	pto := p.rtt() + max(4*p.rttvar, p.cfg.MinPTO) + p.cfg.MaxAckDelay
	var lost []*sentPkt
	kept := p.sent[:0]
	for _, sp := range p.sent {
		switch {
		case sp.lost:
			if now.Sub(sp.sendTime) < lostRetention {
				kept = append(kept, sp)
			}
		case now.Sub(sp.sendTime) > pto:
			sp.lost = true
			lost = append(lost, sp)
			p.inflight -= sp.size
			kept = append(kept, sp)
		default:
			kept = append(kept, sp)
		}
	}
	clear(p.sent[len(kept):])
	p.sent = kept
	if len(lost) > 0 {
		p.onLoss(len(lost))
	}
	return lost
}

// takeAll empties the in-flight list, for a dead or removed path
func (p *path) takeAll() []*sentPkt {
	var lost []*sentPkt
	for _, sp := range p.sent {
		if !sp.lost {
			lost = append(lost, sp)
		}
	}
	p.sent = nil
	clear(p.outq)
	p.outq = nil
	p.inflight = 0
	p.waitingSince = time.Time{}
	return lost
}

// onRecv updates the receive bitmap and reports whether the packet is a path-level duplicate
func (p *path) onRecv(seq uint32) (dup bool) {
	if !p.recvAny {
		p.recvAny, p.recvLargest, p.recvBitmap = true, seq, 0
		return false
	}
	d := int64(int32(seq - p.recvLargest)) // serial arithmetic
	switch {
	case d > 0:
		if d > 64 {
			p.recvBitmap = 0
		} else {
			p.recvBitmap = p.recvBitmap<<d | 1<<(d-1)
		}
		p.recvLargest = seq
	case d == 0:
		return true
	default:
		d = -d
		if d > 64 {
			return true
		}
		bit := uint64(1) << (d - 1)
		if p.recvBitmap&bit != 0 {
			return true
		}
		p.recvBitmap |= bit
	}
	return false
}

package netem

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Stack is a client/server tunnel pair under test, connected over emulated paths
type Stack interface {
	OpenStream() (net.Conn, error)   // opens a reliable client->server stream
	OpenDatagram() (net.Conn, error) // opens an unreliable client->server datagram flow
	Accept() <-chan net.Conn         // server side of streams and datagram flows, in open order
	Close() error
}

// Result summarizes one workload run
type Result struct {
	Name       string
	Duration   time.Duration
	Bytes      uint64        // payload bytes received by the server
	Throughput float64       // bytes/sec
	LatP50     time.Duration // one-way latency of stamped blocks or datagrams
	LatP99     time.Duration
	Sent       uint64        // datagrams sent (datagram workloads only)
	Received   uint64        // datagrams received (datagram workloads only)
	Reordered  uint64        // datagrams that arrived after a higher sequence number
	DepthP99   uint64        // p99 reorder depth in packets (max seen seq - seq) over reordered datagrams
	LateP99    time.Duration // p99 of how long reordered datagrams trailed the newest one
	Errors     int           // stream errors seen during the run
	Extra      string        // stack-specific counters such as retransmissions
	Timeline   []int64       // received bytes per 250 ms bucket
}

func (r Result) String() string {
	s := fmt.Sprintf("%-22s %7.0f KB/s  p50 %6s  p99 %6s  errors %d", r.Name, r.Throughput/1024, r.LatP50.Round(time.Millisecond), r.LatP99.Round(time.Millisecond), r.Errors)
	if r.Sent > 0 {
		loss := 100 * (1 - float64(r.Received)/float64(r.Sent))
		s += fmt.Sprintf("  loss %.1f%%  reordered %.2f%% (depth p99 %d, late p99 %s)", loss, 100*float64(r.Reordered)/float64(max(r.Received, 1)), r.DepthP99, r.LateP99.Round(time.Millisecond))
	}
	if r.Extra != "" {
		s += "  " + r.Extra
	}
	return s
}

const (
	blockSize      = 16 * 1024 // stamped block size for stream workloads
	timelineBucket = 250 * time.Millisecond
)

// recorder aggregates received bytes and latencies across goroutines
type recorder struct {
	start time.Time
	mu    sync.Mutex
	lats  []time.Duration
	tl    []int64
	bytes atomic.Uint64
}

func newRecorder() *recorder { return &recorder{start: time.Now()} }

func (r *recorder) add(n int, lat time.Duration) {
	r.bytes.Add(uint64(n))
	b := int(time.Since(r.start) / timelineBucket)
	r.mu.Lock()
	for len(r.tl) <= b {
		r.tl = append(r.tl, 0)
	}
	r.tl[b] += int64(n)
	if lat >= 0 {
		r.lats = append(r.lats, lat)
	}
	r.mu.Unlock()
}

func (r *recorder) fill(res *Result, warmup time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lats := slices.Clone(r.lats)
	slices.Sort(lats)
	if len(lats) > 0 {
		res.LatP50 = lats[len(lats)/2]
		res.LatP99 = lats[len(lats)*99/100]
	}
	res.Timeline = slices.Clone(r.tl)
	// throughput excludes the warmup buckets so slow start does not dominate short runs
	skip := int(warmup / timelineBucket)
	var total int64
	for i := skip; i < len(r.tl); i++ {
		total += r.tl[i]
	}
	span := res.Duration - warmup
	if span > 0 {
		res.Throughput = float64(total) / span.Seconds()
	}
	res.Bytes = r.bytes.Load()
}

// StreamOptions configures RunStreams
type StreamOptions struct {
	Streams  int
	Duration time.Duration
	Warmup   time.Duration
	During   func(elapsed time.Duration) // called every 250 ms, for fault injection
}

// RunStreams pushes data over parallel streams for a fixed time and measures what arrives
func RunStreams(name string, st Stack, opt StreamOptions) Result {
	res := Result{Name: name, Duration: opt.Duration}
	rec := newRecorder()
	stop := make(chan struct{})
	var errs atomic.Int32
	var wg sync.WaitGroup

	// server readers
	go func() {
		for i := 0; i < opt.Streams; i++ {
			conn, ok := <-st.Accept()
			if !ok {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, blockSize)
				for {
					if _, err := io.ReadFull(conn, buf); err != nil {
						select {
						case <-stop:
						default:
							errs.Add(1)
						}
						return
					}
					sent := int64(binary.BigEndian.Uint64(buf))
					rec.add(blockSize, time.Duration(time.Now().UnixNano()-sent))
				}
			}()
		}
	}()

	// client writers
	conns := make([]net.Conn, 0, opt.Streams)
	for i := 0; i < opt.Streams; i++ {
		c, err := st.OpenStream()
		if err != nil {
			res.Errors++
			continue
		}
		conns = append(conns, c)
		go func() {
			buf := make([]byte, blockSize)
			for {
				select {
				case <-stop:
					return
				default:
				}
				binary.BigEndian.PutUint64(buf, uint64(time.Now().UnixNano()))
				if _, err := c.Write(buf); err != nil {
					select {
					case <-stop:
					default:
						errs.Add(1)
					}
					return
				}
			}
		}()
	}

	runFor(opt.Duration, opt.During)
	close(stop)
	for _, c := range conns {
		_ = c.Close()
	}
	res.Errors += int(errs.Load())
	rec.fill(&res, opt.Warmup)
	return res
}

// DatagramOptions configures RunDatagrams
type DatagramOptions struct {
	Rate     float64 // offered load in bytes/sec
	Size     int     // datagram size
	Duration time.Duration
	Warmup   time.Duration
}

// RunDatagrams sends paced datagrams and measures delivery, latency and reordering
func RunDatagrams(name string, st Stack, opt DatagramOptions) Result {
	if opt.Size < 16 {
		opt.Size = 1200
	}
	res := Result{Name: name, Duration: opt.Duration}
	rec := newRecorder()
	stop := make(chan struct{})

	c, err := st.OpenDatagram()
	if err != nil {
		res.Errors++
		return res
	}
	var recvd, reordered atomic.Uint64
	var depthMu sync.Mutex
	var depths []uint64
	var lates []time.Duration
	go func() {
		srv, ok := <-st.Accept()
		if !ok {
			return
		}
		buf := make([]byte, 65536)
		var maxSeq uint64
		var maxAt time.Time
		for {
			n, err := srv.Read(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			seq := binary.BigEndian.Uint64(buf[8:])
			if seq < maxSeq {
				reordered.Add(1)
				depthMu.Lock()
				depths = append(depths, maxSeq-seq)
				lates = append(lates, time.Since(maxAt))
				depthMu.Unlock()
			} else {
				maxSeq, maxAt = seq, time.Now()
			}
			recvd.Add(1)
			rec.add(n, time.Duration(time.Now().UnixNano()-int64(binary.BigEndian.Uint64(buf))))
		}
	}()

	var sent uint64
	go func() {
		buf := make([]byte, opt.Size)
		interval := time.Duration(float64(time.Second) * float64(opt.Size) / opt.Rate)
		next := time.Now()
		for seq := uint64(1); ; seq++ {
			select {
			case <-stop:
				return
			default:
			}
			binary.BigEndian.PutUint64(buf, uint64(time.Now().UnixNano()))
			binary.BigEndian.PutUint64(buf[8:], seq)
			_, _ = c.Write(buf)
			atomic.AddUint64(&sent, 1)
			next = next.Add(interval)
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
		}
	}()

	runFor(opt.Duration, nil)
	close(stop)
	time.Sleep(300 * time.Millisecond) // let in-flight datagrams land
	_ = c.Close()
	res.Sent = atomic.LoadUint64(&sent)
	res.Received = recvd.Load()
	res.Reordered = reordered.Load()
	depthMu.Lock()
	slices.Sort(depths)
	slices.Sort(lates)
	if len(depths) > 0 {
		res.DepthP99 = depths[len(depths)*99/100]
		res.LateP99 = lates[len(lates)*99/100]
	}
	depthMu.Unlock()
	rec.fill(&res, opt.Warmup)
	return res
}

func runFor(d time.Duration, during func(time.Duration)) {
	start := time.Now()
	t := time.NewTicker(timelineBucket)
	defer t.Stop()
	for time.Since(start) < d {
		<-t.C
		if during != nil {
			during(time.Since(start))
		}
	}
}

// RecoveryTime returns how long after at the timeline first reaches frac of the pre-fault rate
func RecoveryTime(tl []int64, at time.Duration, frac float64) time.Duration {
	k := int(at / timelineBucket)
	if k < 4 || k >= len(tl) {
		return -1
	}
	var before int64
	for _, v := range tl[k-4 : k] {
		before += v
	}
	target := float64(before) / 4 * frac
	// require a full second of sustained rate to count as recovered
	for i := k; i+4 <= len(tl); i++ {
		var sum int64
		for _, v := range tl[i : i+4] {
			sum += v
		}
		if float64(sum)/4 >= target {
			return time.Duration(i-k) * timelineBucket
		}
	}
	return -1
}

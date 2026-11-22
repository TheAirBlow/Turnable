package mpath

import (
	"testing"
	"time"
)

// the session must find capacity that appears after it settled on a slow link
func TestSessionFollowsCapacityUp(t *testing.T) {
	if testing.Short() {
		t.Skip("runs in real time")
	}
	const slow, fast = 100 * 1024, 800 * 1024
	up := &simLink{rate: slow, owd: 45 * time.Millisecond, maxQueue: 1500 * time.Millisecond}
	down := &simLink{rate: 4 * fast, owd: 45 * time.Millisecond, maxQueue: 1500 * time.Millisecond}
	n := newSimNet(t, 4, up, down, Config{}, nil)
	got := pump(n.cli, n.srv)
	rate := measure(got, 20*time.Second, 5*time.Second, func(el time.Duration) {
		if el == 6*time.Second {
			up.setRate(fast)
		}
	})
	if rate < 0.7*fast {
		t.Fatalf("goodput %.0f KB/s over the last 5s of a %d KB/s link, want at least %.0f KB/s", rate/1024, fast/1024, 0.7*fast/1024)
	}
}

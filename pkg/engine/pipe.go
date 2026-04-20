package engine

import (
	"io"
	"log/slog"
	"sync"
)

// pipeCopyChunkSize is the buffer size used when copying between two streams.
// Kept at 32 KB so a single write produces fewer KCP segments (~22) and does not
// saturate the per-flow send queue in one shot.
const pipeCopyChunkSize = 32 * 1024

// pipeStreams copies data bidirectionally, blocking until both directions finish.
func pipeStreams(a, b io.ReadWriteCloser) {
	var hardCloseOnce sync.Once
	hardClose := func() {
		hardCloseOnce.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	runCopy := func(direction string, dst io.ReadWriteCloser, src io.ReadWriteCloser) {
		defer wg.Done()

		n, err := copyStream(dst, src)
		if err != nil {
			slog.Debug("pipe copy done", "direction", direction, "bytes", n, "error", err)
		} else {
			slog.Debug("pipe copy done", "direction", direction, "bytes", n)
		}

		hardClose()
	}

	go runCopy("a->b", b, a)
	go runCopy("b->a", a, b)

	wg.Wait()
	hardClose()
}

// copyStream copies from source to destination until EOF or error
func copyStream(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, pipeCopyChunkSize)
	var total int64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return total, err
			}
			total += int64(n)
		}

		if readErr != nil {
			return total, readErr
		}
	}
}

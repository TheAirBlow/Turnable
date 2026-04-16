package engine

import (
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/theairblow/turnable/pkg/common"
)

// pipeCopyChunkSize is the buffer size used when copying between two streams.
const pipeCopyChunkSize = 64 * 1024

// pipeStreams copies bidirectionally between a and b, blocking until both directions finish.
// Both streams are closed when done.
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
		n, err := copyStream(direction, dst, src)
		if err != nil && !errors.Is(err, io.EOF) {
			slog.Debug("pipe copy stopped", "direction", direction, "bytes", n, "error", err)
			hardClose()
			return
		}
		slog.Debug("pipe copy done", "direction", direction, "bytes", n)
		if cwErr := closeWrite(dst); cwErr != nil {
			hardClose()
		}
	}

	go runCopy("a->b", b, a)
	go runCopy("b->a", a, b)

	wg.Wait()
	hardClose()
}

// copyStream copies from src to dst until EOF or error.
func copyStream(direction string, dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, pipeCopyChunkSize)
	var total int64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			slog.Debug("pipe chunk", "direction", direction, "bytes", n)
			if err := common.WriteFullRetry(dst, buf[:n]); err != nil {
				return total, err
			}
			total += int64(n)
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

// closeWrite attempts a half-close on dst. Silently ignored if unsupported.
func closeWrite(stream io.ReadWriteCloser) error {
	if cw, ok := stream.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

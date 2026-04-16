package common

import (
	"bufio"
	"errors"
	"io"
	"net"
	"time"
)

// BufferedReadWriteCloser wraps a ReadWriteCloser with a buffered reader.
type BufferedReadWriteCloser struct {
	io.ReadWriteCloser
	reader *bufio.Reader
}

// Read reads from the buffered reader.
func (b *BufferedReadWriteCloser) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

// WrapBufferedReadStream wraps stream reads with a buffered reader while preserving writes/closes.
func WrapBufferedReadStream(stream io.ReadWriteCloser, size int) io.ReadWriteCloser {
	if size <= 0 {
		size = 16 * 1024
	}
	return &BufferedReadWriteCloser{
		ReadWriteCloser: stream,
		reader:          bufio.NewReaderSize(stream, size),
	}
}

// ReadFullRetry behaves like io.ReadFull but tolerates temporary transport errors.
func ReadFullRetry(r io.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err == nil {
			continue
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Temporary() {
			if netErr.Timeout() {
				return total, err
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}

		if errors.Is(err, io.EOF) && total > 0 {
			return total, io.ErrUnexpectedEOF
		}
		return total, err
	}
	return total, nil
}

// WriteFullRetry writes the entire buffer, retrying on temporary transport errors.
func WriteFullRetry(w io.Writer, buf []byte) error {
	written := 0
	for written < len(buf) {
		n, err := w.Write(buf[written:])
		if n > 0 {
			written += n
		}
		if err == nil {
			continue
		}

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Temporary() {
			if netErr.Timeout() {
				return err
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		return err
	}
	return nil
}

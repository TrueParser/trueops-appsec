package appsec

import (
	"bytes"
	"io"
	"sync"
)

// uploadBody permits net/http's concurrent Close and signals when transport no
// longer reads the capture. It owns immutable bytes; no pooled buffers escape.
type uploadBody struct {
	mu     sync.Mutex
	reader *bytes.Reader
	closed chan struct{}
	done   bool
}

func newUploadBody(body []byte) *uploadBody {
	return &uploadBody{reader: bytes.NewReader(body), closed: make(chan struct{})}
}

func (b *uploadBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return 0, io.ErrClosedPipe
	}
	return b.reader.Read(p)
}

func (b *uploadBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.done {
		b.done = true
		close(b.closed)
	}
	return nil
}

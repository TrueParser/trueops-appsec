package appsec

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// replayBody preserves the original body's Close contract and trailer state.
type replayBody struct {
	*bytes.Reader
	io.Closer
}

func (h *Handler) capture(r *http.Request) ([]byte, int) {
	if r.Body == nil || r.Body == http.NoBody {
		if r.ContentLength > 0 {
			return nil, http.StatusBadRequest
		}
		return nil, 0
	}
	for _, encoding := range r.Header.Values("Content-Encoding") {
		for coding := range strings.SplitSeq(encoding, ",") {
			if !strings.EqualFold(strings.TrimSpace(coding), "identity") {
				return nil, http.StatusUnsupportedMediaType
			}
		}
	}
	if r.ContentLength > h.MaxBodyBytes {
		return nil, http.StatusRequestEntityTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, h.MaxBodyBytes+1))
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return nil, http.StatusRequestTimeout
		}
		return nil, http.StatusBadRequest
	}
	if int64(len(body)) > h.MaxBodyBytes {
		return nil, http.StatusRequestEntityTooLarge
	}
	if r.ContentLength >= 0 && int64(len(body)) != r.ContentLength {
		return nil, http.StatusBadRequest
	}
	r.Body = &replayBody{Reader: bytes.NewReader(body), Closer: r.Body}
	return body, 0
}

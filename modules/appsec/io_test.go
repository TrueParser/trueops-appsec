package appsec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type failingReader struct{ err error }

func (b failingReader) Read(p []byte) (int, error) { return copy(p, "prefix"), b.err }

type readTimeout struct{}

func (readTimeout) Error() string   { return "fixture read timeout" }
func (readTimeout) Timeout() bool   { return true }
func (readTimeout) Temporary() bool { return false }

func TestBodyCaptureCompletenessAndErrors(t *testing.T) {
	var calls atomic.Int32
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		data, err := io.ReadAll(r.Body)
		if err != nil || string(data) != "complete" || r.ContentLength != 8 {
			t.Error("incomplete native body")
		}
		reply(w, 200, `{"action":"allow"}`)
	}))
	defer engine.Close()
	h := configured(t, engine.URL, true, false, func(h *Handler) { h.MaxBodyBytes = 8 })
	for _, tc := range []struct {
		name     string
		reader   io.Reader
		length   int64
		encoding string
		want     int
	}{
		{"exact", strings.NewReader("complete"), 8, "", 201},
		{"chunked", strings.NewReader("complete"), -1, "", 201},
		{"overflow_known", strings.NewReader("complete!"), 9, "", 413},
		{"overflow_chunked", strings.NewReader("complete!"), -1, "", 413},
		{"short", strings.NewReader("short"), 8, "", 400},
		{"unexpected_eof", failingReader{io.ErrUnexpectedEOF}, -1, "", 400},
		{"read_error", failingReader{errors.New("fixture")}, -1, "", 400},
		{"timeout", failingReader{readTimeout{}}, -1, "", 408},
		{"compressed", strings.NewReader("complete"), 8, "gzip", 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := incoming("POST", "http://site.test/upload", "")
			r.Body = io.NopCloser(tc.reader)
			r.ContentLength = tc.length
			if tc.encoding != "" {
				r.Header.Set("Content-Encoding", tc.encoding)
			}
			before := calls.Load()
			w, called := execute(t, h, r)
			if w.Code != tc.want || called != (tc.want == 201) {
				t.Fatalf("status=%d next=%v", w.Code, called)
			}
			if !called && calls.Load() != before {
				t.Fatal("bad body was inspected")
			}
		})
	}
}

func TestResponseLimitAndEngineReadFailures(t *testing.T) {
	for _, status := range []int{200, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reply(w, status, strings.Repeat("x", 1025)) }))
			defer engine.Close()
			h := configured(t, engine.URL, true, true, func(h *Handler) { h.MaxResponseBytes = 1024 })
			w, called := execute(t, h, incoming("GET", "http://site.test/", ""))
			want := 503
			if status == 403 {
				want = 403
			}
			if w.Code != want || called {
				t.Fatal("oversize response accepted")
			}
		})
	}
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		reply(w, 200, `{"action":"allow"}`)
	}))
	defer engine.Close()
	w, called := execute(t, configured(t, engine.URL, true, false), incoming("GET", "http://site.test/", ""))
	if called || w.Code != 503 {
		t.Fatal("truncated native response allowed")
	}
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("fixture synchronization timed out")
		var zero T
		return zero
	}
}

func TestCapacityCleanupAndActiveBodyOwnership(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		close(entered)
		<-release
		reply(w, 200, `{"action":"allow"}`)
	}))
	defer func() { once.Do(func() { close(release) }); engine.Close() }()
	h := configured(t, engine.URL, true, false, func(h *Handler) { h.MaxInFlight = 1 })
	done := make(chan error, 1)
	go func() {
		done <- h.ServeHTTP(httptest.NewRecorder(), incoming("POST", "http://site.test/upload", "owned-body"), caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return err
			}
			if string(body) != "owned-body" {
				return errors.New("body lost during cleanup")
			}
			return nil
		}))
	}()
	await(t, entered)
	w, called := execute(t, h, incoming("GET", "http://site.test/", ""))
	if called || w.Code != 503 {
		t.Fatal("capacity was not bounded")
	}
	if err := h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if len(h.runtime.slots) != 1 {
		t.Fatal("cleanup prematurely released capture")
	}
	once.Do(func() { close(release) })
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if len(h.runtime.slots) != 0 {
		t.Fatal("capture reservation leaked")
	}
}

func TestTimeoutCancellationAndMissingIdentity(t *testing.T) {
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer engine.Close()
	h := configured(t, engine.URL, true, false, func(h *Handler) { h.Timeout = caddy.Duration(30 * time.Millisecond) })
	w, called := execute(t, h, incoming("GET", "http://site.test/", ""))
	if called || w.Code != 503 || len(h.runtime.slots) != 0 {
		t.Fatal("timeout allowed/leaked a request")
	}
	r := incoming("POST", "http://site.test/", "body")
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	w, called = execute(t, h, r.WithContext(ctx))
	if called || w.Code != 503 {
		t.Fatal("canceled request allowed")
	}
	r = httptest.NewRequest("GET", "http://site.test/", nil)
	r.Header.Set("X-Crowdsec-Appsec-Ip", "192.0.2.8")
	w, called = execute(t, h, r)
	if called || w.Code != 503 {
		t.Fatal("public header supplied trusted identity")
	}
}

func TestConnectionsReusedAndRetiredAfterCleanup(t *testing.T) {
	var conns atomic.Int32
	engine := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"action":"allow"}`) }))
	engine.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	engine.Start()
	defer engine.Close()
	h := configured(t, engine.URL, true, false)
	for range 3 {
		_, called := execute(t, h, incoming("GET", "http://site.test/", ""))
		if !called {
			t.Fatal("allow did not continue")
		}
	}
	if conns.Load() != 1 {
		t.Fatalf("connections=%d, expected reuse", conns.Load())
	}
	if err := h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	_, called := execute(t, h, incoming("GET", "http://site.test/", ""))
	if !called || conns.Load() != 2 {
		t.Fatal("old-chain request was canceled or retired connection reused")
	}
}

func TestSitesDoNotSharePoliciesOrCachedAllows(t *testing.T) {
	var denyCalls, allowCalls atomic.Int32
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		denyCalls.Add(1)
		reply(w, 403, `{"action":"ban","http_status":429}`)
	}))
	defer deny.Close()
	allow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { allowCalls.Add(1); reply(w, 200, `{"action":"allow"}`) }))
	defer allow.Close()
	a, b := configured(t, deny.URL, true, true), configured(t, allow.URL, true, false)
	for range 2 {
		r := incoming("GET", "http://a.test/", "")
		r.Header.Set("Cookie", "native-bot-cookie")
		w, called := execute(t, a, r)
		if called || w.Code != 429 {
			t.Fatal("site A policy lost")
		}
		_, called = execute(t, b, incoming("GET", "http://b.test/", ""))
		if !called {
			t.Fatal("site A affected site B")
		}
	}
	if denyCalls.Load() != 2 || allowCalls.Load() != 2 {
		t.Fatal("cookie or prior result bypassed inspection")
	}
}

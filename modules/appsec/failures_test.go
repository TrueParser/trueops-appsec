package appsec

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

type bodyOnClose struct {
	io.Reader
	close func() error
}

func (b bodyOnClose) Close() error { return b.close() }

func TestLifecycleAndBodyBoundaryFailures(t *testing.T) {
	h := &Handler{WAF: true}
	w, called := execute(t, h, incoming("GET", "http://site.test/", ""))
	if called || w.Code != 503 {
		t.Fatal("unprovisioned handler allowed")
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := h.Provision(ctx); err == nil {
		t.Fatal("invalid configuration provisioned")
	}
	h = configured(t, "http://fixture.invalid/", true, false)
	r := incoming("POST", "http://site.test/", "")
	r.Body = http.NoBody
	r.ContentLength = 1
	w, called = execute(t, h, r)
	if called || w.Code != 400 {
		t.Fatal("missing framed body allowed")
	}
	h.runtime.logger = zap.NewNop()
	// Disabled debug logging is a supported production mode, including failures.
	w, called = execute(t, h, r)
	if called || w.Code != 400 {
		t.Fatal("logging changed enforcement")
	}
	b := newUploadBody([]byte("body"))
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("closed transport body remained readable")
	}
}

func TestRedirectsDoNotForwardEngineCredentials(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); reply(w, 200, `{"action":"allow"}`) }))
	defer target.Close()
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer engine.Close()
	w, called := execute(t, configured(t, engine.URL, true, false), incoming("GET", "http://site.test/", ""))
	if called || w.Code != 503 || forwarded.Load() != 0 {
		t.Fatal("redirect followed or credential leaked")
	}
}

func TestCancellationDuringUploadAndAfterEngineDecision(t *testing.T) {
	for _, which := range []string{"write_not_finished", "canceled_after_allow", "canceled_after_deny"} {
		t.Run(which, func(t *testing.T) {
			h := configured(t, "http://fixture.invalid/", true, true, func(h *Handler) { h.Timeout = caddy.Duration(30 * time.Millisecond) })
			r := incoming("POST", "http://site.test/", "body")
			parent, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(parent)
			h.runtime.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if err := req.Body.Close(); err != nil {
					return nil, err
				}
				if which != "write_not_finished" {
					httptrace.ContextClientTrace(req.Context()).WroteRequest(httptrace.WroteRequestInfo{})
				}
				status, body := 200, `{"action":"allow"}`
				if which == "canceled_after_deny" {
					status, body = 403, `{"action":"ban"}`
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: bodyOnClose{Reader: strings.NewReader(body), close: func() error { cancel(); return nil }}}, nil
			})
			w, called := execute(t, h, r)
			if called || w.Code != 503 || len(h.runtime.slots) != 0 {
				t.Fatal("cancellation allowed or retained work")
			}
		})
	}
}

func TestPrivateCAFileAndCaddyfileCAParsing(t *testing.T) {
	var h Handler
	fixture := strings.Replace(configFixture, "http://127.0.0.1:7422/", "https://engine.test/", 1)
	fixture = strings.Replace(fixture, "timeout 2s", "ca_file missing-ca.pem\n timeout 2s", 1)
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(fixture)); err != nil || h.CAFile != "missing-ca.pem" {
		t.Fatalf("CA parse: %v", err)
	}
	h.CAFile = filepath.Join(t.TempDir(), "private-path-that-must-not-leak.pem")
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := h.Provision(ctx); err == nil || strings.Contains(err.Error(), "private-path") {
		t.Fatal("missing CA file accepted or path exposed")
	}
}

func TestPrivateCAFailsClosedWhenSystemRootsCannotLoad(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &Handler{CAFile: caFile}
	called := false
	client, err := h.newClient(func() (*x509.CertPool, error) {
		called = true
		return nil, errors.New("fixture-sensitive-root-store-error")
	})
	if !called || client != nil || err == nil || err.Error() != "appsec: cannot load system certificate roots" {
		t.Fatalf("root-store failure accepted or disclosed: client=%v, err=%v", client, err)
	}
}

func TestCompletedUploadCancellationRaceNeverAllows(t *testing.T) {
	h := configured(t, "http://fixture.invalid/", true, false)
	// Both completion and cancellation may be ready when inspection selects.
	// Repeated exchanges exercise the race; neither outcome may invoke next.
	for range 32 {
		r := incoming("POST", "http://site.test/", "body")
		parent, cancel := context.WithCancel(r.Context())
		r = r.WithContext(parent)
		h.runtime.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if err := req.Body.Close(); err != nil {
				return nil, err
			}
			httptrace.ContextClientTrace(req.Context()).WroteRequest(httptrace.WroteRequestInfo{})
			cancel()
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"action":"allow"}`))}, nil
		})
		w, called := execute(t, h, r)
		cancel()
		if called || w.Code != 503 || len(h.runtime.slots) != 0 {
			t.Fatal("simultaneous upload completion and cancellation allowed or retained work")
		}
	}
}

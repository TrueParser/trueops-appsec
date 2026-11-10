package appsec

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closeNotice struct {
	io.Reader
	closed chan struct{}
}

func (b closeNotice) Close() error { close(b.closed); return nil }

func TestEarlyAllowAndDelayedUploadCloseRetainReservation(t *testing.T) {
	h := configured(t, "http://fixture.invalid/", true, false, func(h *Handler) { h.MaxInFlight = 1 })
	bodyClosed := make(chan struct{})
	outbound := make(chan io.ReadCloser, 1)
	h.runtime.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		outbound <- r.Body
		trace := httptrace.ContextClientTrace(r.Context())
		trace.WroteRequest(httptrace.WroteRequestInfo{Err: errors.New("fixture incomplete upload")})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: closeNotice{Reader: strings.NewReader(`{"action":"allow"}`), closed: bodyClosed}}, nil
	})
	done := make(chan error, 1)
	w := httptest.NewRecorder()
	next := false
	go func() {
		done <- h.ServeHTTP(w, incoming("POST", "http://site.test/", "captured body"), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { next = true; return nil }))
	}()
	upload := await(t, outbound)
	// Always unblock the transport fixture even if an assertion fails.
	defer upload.Close()
	await(t, bodyClosed)
	if len(h.runtime.slots) != 1 {
		t.Fatal("response closed but live upload lost its reservation")
	}
	if err := h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := upload.Close(); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if next || w.Code != 503 || len(h.runtime.slots) != 0 {
		t.Fatal("incomplete transfer became allow or leaked capacity")
	}
}

func TestHTTP2EngineUsesNativeIdentityAndCompleteBody(t *testing.T) {
	engine := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.ProtoMajor != 2 || string(body) != "complete-h2" || r.Header.Get("X-Crowdsec-Appsec-Http-Version") != "20" {
			t.Error("HTTP/2 inspection changed")
		}
		reply(w, 200, `{"action":"allow"}`)
	}))
	engine.EnableHTTP2 = true
	engine.StartTLS()
	defer engine.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: engine.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	h := configured(t, engine.URL, true, true, func(h *Handler) { h.CAFile = ca })
	r := incoming("POST", "http://site.test/", "complete-h2")
	r.ProtoMajor = 2
	r.ProtoMinor = 0
	r.ContentLength = -1
	w, called := execute(t, h, r)
	if !called || w.Body.String() != "complete-h2" {
		t.Fatal("HTTP/2 allow did not preserve full body")
	}
}

func TestDiagnosticsExcludeRequestAndEngineSecrets(t *testing.T) {
	// Use the real configured logger; request/engine payloads are never log fields.
	h := configured(t, "http://fixture.invalid/", true, true)
	core, logs := observer.New(zap.DebugLevel)
	h.runtime.logger = zap.New(zapcore.NewTee(h.runtime.logger.Core(), core))
	r := incoming("POST", "http://site.test/", "private-payload")
	// A nonconforming test transport must still honor the real RoundTripper
	// ownership contract, including closing request bodies on error.
	h.runtime.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.Body.Close(); err != nil {
			return nil, err
		}
		return nil, errors.New("fixture-sensitive-engine-error")
	})
	w, called := execute(t, h, r)
	if called || w.Code != 503 || strings.Contains(w.Body.String(), "fixture-sensitive") {
		t.Fatal("error detail exposed")
	}
	encoded, err := json.Marshal(logs.All())
	if err != nil {
		t.Fatal(err)
	}
	if logs.Len() == 0 {
		t.Fatal("diagnostics were not exercised")
	}
	for _, secret := range []string{"private-payload", "fixture-sensitive-engine-error", "fixture-engine-key"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("secret leaked into diagnostics")
		}
	}
}

func TestChallengeHeaderAliasesPreserveEveryNativeValue(t *testing.T) {
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reply(w, 403, `{"action":"challenge","user_body_content":"challenge","user_headers":{"Content-Security-Policy":["policy-one"],"content-security-policy":["policy-two"]}}`)
	}))
	defer engine.Close()
	w, called := execute(t, configured(t, engine.URL, true, true), incoming("GET", "http://site.test/", ""))
	if called || w.Code != 200 || len(w.Header().Values("Content-Security-Policy")) != 2 {
		t.Fatalf("native header values lost: status=%d next=%v CSP=%v", w.Code, called, w.Header().Values("Content-Security-Policy"))
	}
}

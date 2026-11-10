package appsec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func configured(t *testing.T, endpoint string, waf, bot bool, options ...func(*Handler)) *Handler {
	t.Helper()
	h := &Handler{WAF: waf, Bot: bot, Endpoint: endpoint, APIKey: "fixture-engine-key",
		Timeout: caddy.Duration(2 * time.Second), MaxBodyBytes: 64 << 10, MaxResponseBytes: 128 << 10, MaxInFlight: 4}
	for _, option := range options {
		option(h)
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if h.runtime != nil {
		h.runtime.logger = zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))
	}
	t.Cleanup(func() {
		if err := h.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return h
}

func incoming(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: "192.0.2.8"})
	return r.WithContext(ctx)
}

func reply(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func execute(t *testing.T, h *Handler, r *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	w := httptest.NewRecorder()
	called := false
	err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusCreated)
		_, err := io.Copy(w, r.Body)
		return err
	}))
	if err != nil {
		t.Fatal(err)
	}
	return w, called
}

type unreadableBody struct{ reads int }

func (b *unreadableBody) Read([]byte) (int, error) { b.reads++; return 0, errors.New("must not read") }
func (*unreadableBody) Close() error               { return nil }

func TestDisabledPathIsUntouchedAndAddsNoAllocations(t *testing.T) {
	h := configured(t, "invalid endpoint is unused", false, false)
	r := incoming(http.MethodPost, "http://site.test"+challengePrefix+"submit", "")
	body := &unreadableBody{}
	r.Body = body
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, got *http.Request) error {
		if got != r || got.Body != body {
			t.Fatal("disabled request was replaced")
		}
		return nil
	})
	w := httptest.NewRecorder()
	baseline := testing.AllocsPerRun(1000, func() {
		if err := next.ServeHTTP(w, r); err != nil {
			panic(err)
		}
	})
	withModule := testing.AllocsPerRun(1000, func() {
		if err := h.ServeHTTP(w, r, next); err != nil {
			panic(err)
		}
	})
	t.Logf("allocations/request baseline=%g disabled=%g added=%g", baseline, withModule, withModule-baseline)
	if withModule != baseline || body.reads != 0 || h.runtime != nil {
		t.Fatal("disabled path performed security work")
	}
}

func TestNativeInspectionPreservesRequestAndAllPolicyModes(t *testing.T) {
	for _, mode := range []struct {
		name     string
		waf, bot bool
	}{
		{"off", false, false}, {"waf", true, false}, {"bot", false, true}, {"combined", true, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var calls atomic.Int32
			payload := "entire body including final marker: END"
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				data, err := io.ReadAll(r.Body)
				if err != nil || string(data) != payload || r.ContentLength != int64(len(payload)) || r.Method != "POST" {
					t.Error("inspection body/method mismatch")
				}
				for name, want := range map[string]string{
					"X-Crowdsec-Appsec-Ip": "192.0.2.8", "X-Crowdsec-Appsec-Host": "site.test:8080",
					"X-Crowdsec-Appsec-Uri": "/a%2Fb?q=1&q=2", "X-Crowdsec-Appsec-Verb": "PATCH",
					"X-Crowdsec-Appsec-Api-Key": "fixture-engine-key", "X-Crowdsec-Appsec-User-Agent": "fixture-browser",
					"X-Crowdsec-Appsec-Http-Version": "11", "Cookie": "__crowdsec_challenge=opaque",
				} {
					if r.Header.Get(name) != want {
						t.Errorf("%s mismatch", name)
					}
				}
				if r.Header.Get("X-Hop") != "" || r.Header.Get("X-Crowdsec-Appsec-Profile") != "" {
					t.Error("public integration/hop metadata leaked")
				}
				if len(r.Header.Values("X-Repeated")) != 2 {
					t.Error("repeated headers collapsed")
				}
				reply(w, 200, `{"action":"allow"}`)
			}))
			defer engine.Close()
			h := configured(t, engine.URL, mode.waf, mode.bot)
			r := incoming("PATCH", "http://site.test:8080/a%2Fb?q=1&q=2", payload)
			r.Header.Set("Cookie", "__crowdsec_challenge=opaque")
			r.Header.Set("User-Agent", "fixture-browser")
			r.Header.Set("X-Crowdsec-Appsec-Ip", "203.0.113.99")
			r.Header.Set("X-Crowdsec-Appsec-Api-Key", "untrusted-key")
			r.Header.Set("X-Crowdsec-Appsec-Profile", "off")
			r.Header.Set("Connection", "X-Hop")
			r.Header.Set("X-Hop", "remove only from inspection")
			r.Header.Add("X-Repeated", "one")
			r.Header.Add("X-Repeated", "two")
			before, _ := json.Marshal(r.Header)
			w := httptest.NewRecorder()
			called := false
			err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, got *http.Request) error {
				called = true
				after, _ := json.Marshal(got.Header)
				data, err := io.ReadAll(got.Body)
				if got != r || string(before) != string(after) || got.Method != "PATCH" || got.Host != "site.test:8080" || got.URL.RequestURI() != "/a%2Fb?q=1&q=2" || string(data) != payload {
					t.Error("original request changed")
				}
				return err
			}))
			wantCalls := int32(1)
			if !mode.waf && !mode.bot {
				wantCalls = 0
			}
			if err != nil || !called || calls.Load() != wantCalls {
				t.Fatalf("err=%v called=%v inspections=%d", err, called, calls.Load())
			}
		})
	}
}

func TestEngineFailuresAndNativeDenialsNeverContinue(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream int
		body     string
		want     int
	}{
		{"allow", 200, `{"action":"allow"}`, 201},
		{"empty_success", 200, "", 503}, {"malformed_success", 200, "{", 503},
		{"wrong_action", 200, `{"action":"ban"}`, 503}, {"ambiguous", 200, `{"action":"ban","action":"allow"}`, 503},
		{"trailing_json", 200, `{"action":"allow"}{}`, 503}, {"null", 200, `null`, 503},
		{"ban", 403, `{"action":"ban","http_status":403}`, 403},
		{"rate_limit", 403, `{"action":"ban","http_status":429}`, 429},
		{"invalid_ban_status", 403, `{"action":"ban","http_status":200}`, 403},
		{"captcha", 403, `{"action":"captcha"}`, 403}, {"unknown", 403, `{"action":"future"}`, 403},
		{"blocked_allow", 403, `{"action":"allow"}`, 403}, {"empty_denial", 403, "", 403},
		{"broken_denial", 403, "{", 403}, {"unauthorized", 401, "", 503},
		{"unavailable", 500, "", 503}, {"unexpected", 404, "", 503}, {"redirect", 307, "", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reply(w, tc.upstream, tc.body) }))
			defer engine.Close()
			w, called := execute(t, configured(t, engine.URL, true, true), incoming("GET", "http://site.test/", ""))
			if w.Code != tc.want || called != (tc.want == 201) {
				t.Fatalf("status=%d next=%v", w.Code, called)
			}
			if !called && strings.Contains(w.Body.String(), "action") {
				t.Fatal("native envelope exposed")
			}
		})
	}
}

func TestFullChallengeExchangeIsTerminal(t *testing.T) {
	var calls atomic.Int32
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		path := r.Header.Get("X-Crowdsec-Appsec-Uri")
		if r.Header.Get("X-Crowdsec-Appsec-Ip") != "192.0.2.8" {
			t.Error("challenge identity lost")
		}
		if path == challengePrefix+"submit" {
			data, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(data) != "sealed-proof" {
				t.Error("submission changed")
			}
			reply(w, 403, `{"action":"challenge","http_status":200,"user_body_content":"{\"status\":\"ok\"}","user_cookies":["cookie-a=a; Path=/","cookie-b=b; Path=/"],"user_headers":{"Content-Type":["application/json"],"Content-Security-Policy":["default-src 'self'"]}}`)
		} else if strings.Contains(path, ".js") {
			reply(w, 403, `{"action":"challenge","user_body_content":"asset-code","user_headers":{"Content-Type":["application/javascript"]}}`)
		} else if r.Header.Get("Cookie") != "" {
			// A valid Bot cookie must still reach the WAF endpoint on every call.
			reply(w, 403, `{"action":"ban","http_status":403}`)
		} else {
			reply(w, 403, `{"action":"challenge","http_status":307,"user_body_content":"redirect fallback","user_headers":{"Location":["/return"],"Content-Security-Policy":["default-src 'self'; script-src 'unsafe-inline'"]}}`)
		}
	}))
	defer engine.Close()
	h := configured(t, engine.URL, true, true)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/page", "", 307}, {"GET", challengePrefix + "fpscanner.js", "", 200},
		{"GET", challengePrefix + "pow-worker.js", "", 200}, {"GET", challengePrefix + "custom.js", "", 200},
		{"POST", challengePrefix + "submit", "sealed-proof", 200}, {"HEAD", "/page", "", 307},
	} {
		t.Run(tc.path+tc.method, func(t *testing.T) {
			w := httptest.NewRecorder()
			w.Header().Add("Content-Security-Policy", "old-policy")
			next := false
			err := h.ServeHTTP(w, incoming(tc.method, "http://site.test"+tc.path, tc.body), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { next = true; return nil }))
			if err != nil || next || w.Code != tc.status {
				t.Fatalf("err=%v next=%v status=%d", err, next, w.Code)
			}
			if tc.method == "POST" && len(w.Header().Values("Set-Cookie")) != 2 {
				t.Error("cookies collapsed")
			}
			if tc.path == "/page" && (len(w.Header().Values("Content-Security-Policy")) != 1 || strings.Contains(w.Header().Get("Content-Security-Policy"), "old-policy")) {
				t.Error("CSP was not replaced")
			}
			if tc.method == "HEAD" && w.Body.Len() != 0 {
				t.Error("HEAD wrote a body")
			}
		})
	}
	r := incoming("GET", "http://site.test/page", "")
	r.Header.Set("Cookie", "sealed-cookie")
	w, called := execute(t, h, r)
	if w.Code != 403 || called || calls.Load() != 7 {
		t.Fatal("Bot cookie bypassed WAF")
	}
}

func TestInvalidChallengesAndUnknownInternalPaths(t *testing.T) {
	for _, body := range []string{
		`{"action":"challenge","http_status":200}`,
		`{"action":"challenge","http_status":101,"user_body_content":"bad"}`,
		`{"action":"challenge","user_body_content":"bad","user_headers":{"Bad Header":["value"]}}`,
		`{"action":"challenge","user_body_content":"bad","user_headers":{"X-Test":["value\r\ninjected"]}}`,
		`{"action":"challenge","user_body_content":"bad","user_cookies":["cookie=bad\r\ninjected"]}`,
		`{"action":"challenge","user_body_content":"bad","user_headers":{"Connection":["close"]}}`,
	} {
		t.Run(body, func(t *testing.T) {
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reply(w, 403, body) }))
			defer engine.Close()
			w, called := execute(t, configured(t, engine.URL, true, true), incoming("GET", "http://site.test/", ""))
			if w.Code != 403 || called || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("invalid challenge partially applied")
			}
		})
	}
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reply(w, 200, `{"action":"allow"}`) }))
	defer engine.Close()
	w, called := execute(t, configured(t, engine.URL, false, true), incoming("GET", "http://site.test"+challengePrefix+"unknown", ""))
	if w.Code != 404 || called {
		t.Fatal("internal challenge route reached origin")
	}
}

package appsec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestFailureActionConfiguration(t *testing.T) {
	for _, action := range []string{"", "deny", "passthrough"} {
		t.Run("action_"+action, func(t *testing.T) {
			fixture := configFixture
			if action != "" {
				fixture = strings.Replace(fixture, " waf on", " failure_action "+action+"\n waf on", 1)
			}
			var h Handler
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(fixture)); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(h)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Handler
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.FailureAction != action || decoded.Validate() != nil {
				t.Fatal("failure action lost during Caddyfile/JSON round trip")
			}
			t.Logf("failure_action=%q accepted by Caddyfile and JSON configuration", action)
		})
	}
	for _, action := range []string{"allow", "DENY", "secret-invalid"} {
		var h Handler
		fixture := strings.Replace(configFixture, " waf on", " failure_action "+action+"\n waf on", 1)
		if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(fixture)); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid failure action accepted or disclosed")
		}
	}
}

func TestFailureActionHTTPStatuses(t *testing.T) {
	for _, action := range []string{"", "deny", "passthrough"} {
		for _, tc := range []struct {
			name     string
			status   int
			body     string
			eligible bool
			denial   int
		}{
			{"engine_error", 500, "null", true, 503},
			{"authentication", 401, "null", true, 503},
			{"unreachable_gateway", 502, "", true, 503},
			{"unexpected_status", 404, "", true, 503},
			{"redirect", 307, "", true, 503},
			{"ban", 403, `{"action":"ban","http_status":403}`, false, 403},
			{"rate_limit", 403, `{"action":"ban","http_status":429}`, false, 429},
			{"captcha", 403, `{"action":"captcha"}`, false, 403},
			{"blocked_allow", 403, `{"action":"allow"}`, false, 403},
			{"empty_denial", 403, "", false, 403},
			{"broken_denial", 403, "{", false, 403},
			{"malformed_success", 200, "{", false, 503},
			{"wrong_action", 200, `{"action":"ban"}`, false, 503},
			{"invalid_challenge", 403, `{"action":"challenge"}`, false, 403},
			{"challenge", 403, `{"action":"challenge","user_body_content":"native page"}`, false, 200},
			{"challenge_redirect", 403, `{"action":"challenge","http_status":307,"user_body_content":"native redirect","user_headers":{"Location":["/return"]}}`, false, 307},
			{"oversized_envelope", 200, strings.Repeat("x", 129<<10), false, 503},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					reply(w, tc.status, tc.body)
				}))
				defer engine.Close()
				h := configured(t, engine.URL, true, true, func(h *Handler) { h.FailureAction = action })
				w, called := execute(t, h, incoming("PATCH", "http://site.test/path?q=1", "complete captured body"))
				wantPass := action == "passthrough" && tc.eligible
				wantStatus := tc.denial
				if wantPass {
					wantStatus = http.StatusCreated
				}
				if called != wantPass || w.Code != wantStatus || len(h.runtime.slots) != 0 {
					t.Fatalf("status=%d next=%t retained=%d", w.Code, called, len(h.runtime.slots))
				}
				if wantPass && w.Body.String() != "complete captured body" {
					t.Fatal("failure passthrough lost the captured body")
				}
			})
		}
	}
}

func TestFailureActionDisabledPathRemainsUntouched(t *testing.T) {
	h := configured(t, "unused endpoint", false, false, func(h *Handler) { h.FailureAction = "passthrough" })
	body := &unreadableBody{}
	r := incoming("POST", "http://site.test/", "")
	r.Body = body
	called := false
	err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, got *http.Request) error {
		called = true
		if got != r {
			t.Fatal("disabled scope replaced the request")
		}
		return nil
	}))
	if err != nil || !called || body.reads != 0 || h.runtime != nil {
		t.Fatal("failure policy added disabled-path security work")
	}
}

func TestFailurePassthroughTransportAndTimeout(t *testing.T) {
	for _, mode := range []string{"connection", "timeout", "tls"} {
		t.Run(mode, func(t *testing.T) {
			engine := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			}))
			defer engine.Close()
			h := configured(t, engine.URL, true, false, func(h *Handler) {
				h.FailureAction = "passthrough"
				h.Timeout = caddy.Duration(30 * time.Millisecond)
			})
			if mode != "tls" {
				h.runtime.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					_ = r.Body.Close()
					if mode == "timeout" {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					return nil, errors.New("fixture engine unavailable")
				})
			}
			w, called := execute(t, h, incoming("POST", "http://site.test/", "entire body"))
			if !called || w.Code != 201 || w.Body.String() != "entire body" || len(h.runtime.slots) != 0 {
				t.Fatal("explicit transport failure passthrough lost body or retained work")
			}
		})
	}
}

func TestFailurePassthroughCannotBypassLocalBoundaries(t *testing.T) {
	for _, which := range []string{"internal_asset", "internal_submit", "body_read", "framing", "oversize", "identity", "capacity", "canceled", "canceled_during_inspection", "invalid_envelope_read"} {
		t.Run(which, func(t *testing.T) {
			h := configured(t, "http://fixture.invalid/", true, true, func(h *Handler) { h.FailureAction = "passthrough" })
			r := incoming("POST", "http://site.test/path", "captured body")
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			want := 503
			h.runtime.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				_ = req.Body.Close()
				if which == "canceled_during_inspection" {
					cancel()
				}
				if which == "invalid_envelope_read" {
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(io.MultiReader(strings.NewReader(`{"action":"allow"}`), &unreadableBody{}))}, nil
				}
				return nil, errors.New("fixture engine unavailable")
			})
			switch which {
			case "internal_asset":
				r.URL.Path = challengePrefix + "fpscanner.js"
			case "internal_submit":
				r.URL.Path = challengePrefix + "submit"
			case "body_read":
				r.Body, want = &unreadableBody{}, 400
			case "framing":
				r.ContentLength, want = r.ContentLength+1, 400
			case "oversize":
				h.MaxBodyBytes, want = 1, 413
			case "identity":
				r = httptest.NewRequest("GET", "http://site.test/", nil)
			case "capacity":
				for range h.MaxInFlight {
					h.runtime.slots <- struct{}{}
				}
				defer func() {
					for range h.MaxInFlight {
						<-h.runtime.slots
					}
				}()
			case "canceled":
				cancel()
			}
			w, called := execute(t, h, r)
			if called || w.Code != want {
				t.Fatalf("failure policy bypassed %s: status=%d next=%t", which, w.Code, called)
			}
		})
	}
}

func TestFailurePassthroughPreservesOriginalRequestAndScope(t *testing.T) {
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		reply(w, 500, "null")
	}))
	defer engine.Close()
	for _, waf := range []bool{false, true} {
		for _, action := range []string{"passthrough", "deny"} {
			h := configured(t, engine.URL, waf, true, func(h *Handler) { h.FailureAction = action })
			r := incoming("PATCH", "http://site.test:8080/a%2Fb?q=1&q=2", "complete original body")
			r.Header.Set("Cookie", "opaque-cookie")
			before, _ := json.Marshal(r.Header)
			nextError := errors.New("original handler error")
			err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, got *http.Request) error {
				after, _ := json.Marshal(got.Header)
				data, _ := io.ReadAll(got.Body)
				if action != "passthrough" || got != r || string(before) != string(after) || got.Method != "PATCH" || got.Host != "site.test:8080" || got.URL.RequestURI() != "/a%2Fb?q=1&q=2" || string(data) != "complete original body" {
					t.Fatal("scope policy or original request changed")
				}
				return nextError
			}))
			if (action == "passthrough" && !errors.Is(err, nextError)) || (action == "deny" && err != nil) {
				t.Fatal("scope policy or original handler error was lost")
			}
		}
	}
}

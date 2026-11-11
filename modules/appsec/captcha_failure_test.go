package appsec

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestCaptchaProviderTransportFailuresAndCancellation(t *testing.T) {
	for _, which := range []string{"connection", "timeout", "response_read", "canceled", "bad_endpoint"} {
		t.Run(which, func(t *testing.T) {
			h, _ := captchaFixture(t, "turnstile")
			r, _ := captchaSubmission(t, h)
			if which == "timeout" {
				h.Timeout = caddy.Duration(30 * time.Millisecond)
			}
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			if which == "bad_endpoint" {
				h.runtime.captcha.provider.verify = ":invalid"
			}
			h.runtime.captcha.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				_ = req.Body.Close()
				if which == "timeout" {
					<-req.Context().Done()
					return nil, req.Context().Err()
				}
				if which == "connection" {
					return nil, errors.New("fixture provider unavailable")
				}
				if which == "canceled" {
					cancel()
				}
				var response io.Reader = strings.NewReader(`{"success":true,"hostname":"site.test"}`)
				if which == "response_read" {
					response = &unreadableBody{}
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(response)}, nil
			})
			w, called := execute(t, h, r)
			if called || w.Code != 403 || len(w.Result().Cookies()) != 0 {
				t.Fatal("failed/canceled provider verification granted access")
			}
		})
	}
}

func TestCaptchaInternalRoutesDoNotReachOrigin(t *testing.T) {
	allow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reply(w, 200, `{"action":"allow"}`) }))
	defer allow.Close()
	for _, configuredCaptcha := range []bool{false, true} {
		options := []func(*Handler){}
		if configuredCaptcha {
			options = append(options, func(h *Handler) {
				h.Captcha = &CaptchaConfig{Provider: "turnstile", SiteKey: "fixture", SecretKey: "fixture", CookieSecret: strings.Repeat("k", 32)}
			})
		}
		local := configured(t, allow.URL, true, false, options...)
		for _, path := range []string{captchaPrefix + "submit", captchaPrefix + "unknown"} {
			w, called := execute(t, local, incoming("GET", "https://site.test"+path, ""))
			if called || (w.Code != 404 && w.Code != 405) {
				t.Fatal("CAPTCHA internal path reached origin")
			}
		}
	}
	// A native CAPTCHA action for a Bot asset must not serve a provider page.
	h, _ := captchaFixture(t, "turnstile")
	w := httptest.NewRecorder()
	if err := h.renderCaptcha(w, incoming("GET", "https://site.test"+challengePrefix+"fpscanner.js", ""), 200); err != nil || w.Code != 403 {
		t.Fatal("Bot asset was replaced by a provider CAPTCHA")
	}
}

func TestCaptchaDisabledConfigurationDoesNoWork(t *testing.T) {
	h := configured(t, "unused", false, false, func(h *Handler) {
		h.Captcha = &CaptchaConfig{Provider: "unused-invalid-config"}
	})
	body := &unreadableBody{}
	r := incoming("POST", "https://site.test/", "")
	r.Body = body
	called := false
	err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { called = true; return nil }))
	if err != nil || !called || body.reads != 0 || h.runtime != nil {
		t.Fatal("disabled CAPTCHA configuration performed security work")
	}
}

func TestCaptchaNativeConfigurationAndDiagnostics(t *testing.T) {
	fixture := strings.Replace(configFixture, " waf on", " captcha_provider turnstile\n captcha_site_key fixture-public\n captcha_secret_key fixture-private\n captcha_cookie_secret "+strings.Repeat("k", 32)+"\n waf on", 1)
	config := ":8080 {\n route {\n" + fixture + "\n respond ok\n }\n}"
	data, warnings, err := caddyconfig.GetAdapter("caddyfile").Adapt(caddyfile.Format([]byte(config)), nil)
	if err != nil || len(warnings) != 0 || !strings.Contains(string(data), `"captcha"`) {
		t.Fatalf("native CAPTCHA adaptation failed: err=%v warnings=%v", err, warnings)
	}
	h, _ := captchaFixture(t, "turnstile")
	core, logs := observer.New(zap.DebugLevel)
	h.runtime.logger = zap.New(zapcore.NewTee(h.runtime.logger.Core(), core))
	providerFixture(t, h, 200, `{"success":true,"hostname":"site.test"}`)
	r, _ := captchaSubmission(t, h)
	if w, called := execute(t, h, r); called || w.Code != 303 {
		t.Fatal("fixture verification failed")
	}
	for _, entry := range logs.All() {
		for _, field := range entry.Context {
			for _, secret := range []string{h.Captcha.SecretKey, h.Captcha.CookieSecret, "fixture-provider-proof"} {
				if strings.Contains(field.String, secret) {
					t.Fatal("CAPTCHA secret/proof appeared in diagnostics")
				}
			}
		}
	}
	if logs.Len() == 0 {
		t.Fatal("CAPTCHA diagnostics not exercised")
	}
}

func TestCaptchaCleanupDoesNotCancelActiveVerification(t *testing.T) {
	h, _ := captchaFixture(t, "turnstile")
	r, _ := captchaSubmission(t, h)
	started, release := make(chan struct{}), make(chan struct{})
	h.runtime.captcha.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		_ = req.Body.Close()
		close(started)
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"success":true,"hostname":"site.test"}`))}, nil
	})
	w := httptest.NewRecorder()
	done := make(chan error, 1)
	go func() { done <- h.ServeHTTP(w, r, nil) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("verification did not start")
	}
	if err := h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if len(h.runtime.slots) != 1 {
		t.Fatal("reload released active verification ownership")
	}
	close(release)
	if err := await(t, done); err != nil || w.Code != 303 || len(h.runtime.slots) != 0 {
		t.Fatal("reload interrupted verification or leaked ownership")
	}
}

func TestCaptchaTokenEncodingAndSafeWidgetEscaping(t *testing.T) {
	h, _ := captchaFixture(t, "turnstile", func(h *Handler) { h.Captcha.SiteKey = `public"><script>alert(1)</script>` })
	w, called := execute(t, h, incoming("GET", "https://site.test/path", ""))
	if called || strings.Contains(w.Body.String(), `<script>alert(1)</script>`) {
		t.Fatal("site key injected executable HTML")
	}
	r := incoming("GET", "https://site.test/", "")
	for _, payload := range []string{"!", base64.RawURLEncoding.EncodeToString([]byte("invalid JSON"))} {
		token := payload + "." + base64.RawURLEncoding.EncodeToString(h.captchaMAC(r, "grant", payload))
		if _, ok := h.checkCaptcha(r, "grant", token); ok {
			t.Fatal("malformed grant accepted")
		}
	}
	// Verify that a different key cannot authenticate a forged grant.
	mac := hmac.New(sha256.New, []byte("wrong-key"))
	_, _ = mac.Write([]byte("payload"))
	if _, ok := h.checkCaptcha(r, "grant", "payload."+base64.RawURLEncoding.EncodeToString(mac.Sum(nil))); ok {
		t.Fatal("forged MAC accepted")
	}
	if captchaHostname("Site.Test:443") != "site.test" || safeCaptchaReturn("/a%2Fb?q=1&q=2") != "/a%2Fb?q=1&q=2" {
		t.Fatal("safe host/return metadata changed")
	}
}

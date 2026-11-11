package appsec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func captchaFixture(t *testing.T, provider string, options ...func(*Handler)) (*Handler, *atomic.Int32) {
	t.Helper()
	calls := new(atomic.Int32)
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		switch r.Header.Get("X-Crowdsec-Appsec-Uri") {
		case "/ban":
			reply(w, 403, `{"action":"ban","http_status":429}`)
		case "/native":
			reply(w, 403, `{"action":"challenge","user_body_content":"native-bot-page"}`)
		case "/error":
			reply(w, 500, "null")
		case "/allow":
			reply(w, 200, `{"action":"allow"}`)
		default:
			reply(w, 403, `{"action":"captcha","http_status":403}`)
		}
	}))
	t.Cleanup(engine.Close)
	setup := []func(*Handler){func(h *Handler) {
		h.Captcha = &CaptchaConfig{Provider: provider, SiteKey: "fixture-public-site", SecretKey: "fixture-provider-secret", CookieSecret: strings.Repeat("fixture-cookie-key-", 3)}
	}}
	setup = append(setup, options...)
	return configured(t, engine.URL, true, true, setup...), calls
}

func captchaTicket(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("CAPTCHA page has no signed ticket")
	}
	return match[1]
}

func captchaSubmission(t *testing.T, h *Handler) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	page, called := execute(t, h, incoming("GET", "https://site.test/original?q=1&q=2", ""))
	if called || page.Code != 403 {
		t.Fatal("CAPTCHA page reached the original handler")
	}
	form := url.Values{"ticket": {captchaTicket(t, page)}, h.runtime.captcha.provider.field: {"fixture-provider-proof"}}
	r := incoming("POST", "https://site.test"+h.runtime.captcha.submitPath, form.Encode())
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range page.Result().Cookies() {
		r.AddCookie(cookie)
	}
	return r, page
}

func providerFixture(t *testing.T, h *Handler, status int, body string) *atomic.Int32 {
	t.Helper()
	calls := new(atomic.Int32)
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil || r.Method != "POST" || r.Form.Get("secret") != h.Captcha.SecretKey || r.Form.Get("response") != "fixture-provider-proof" || r.Form.Get("remoteip") != "192.0.2.8" {
			t.Error("provider verification request lost proof, identity or credentials")
		}
		if h.Captcha.Provider == "hcaptcha" && r.Form.Get("sitekey") != h.Captcha.SiteKey {
			t.Error("hCaptcha verification is not bound to its site key")
		}
		if r.Header.Get("X-Crowdsec-Appsec-Api-Key") != "" || r.Header.Get("Cookie") != "" {
			t.Error("AppSec credential or browser cookie leaked to CAPTCHA provider")
		}
		reply(w, status, body)
	}))
	t.Cleanup(provider.Close)
	target, _ := url.Parse(provider.URL)
	transport := provider.Client().Transport
	h.runtime.captcha.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != h.runtime.captcha.provider.verify || req.URL.Scheme != "https" {
			t.Error("unexpected public verification endpoint")
		}
		forwarded := req.Clone(req.Context())
		forwarded.URL, forwarded.Host = target, target.Host
		return transport.RoundTrip(forwarded)
	})
	return calls
}

func TestCaptchaProviderExchangesAndWAFIsolation(t *testing.T) {
	for _, provider := range []string{"turnstile", "hcaptcha", "recaptcha"} {
		t.Run(provider, func(t *testing.T) {
			h, inspections := captchaFixture(t, provider)
			providerCalls := providerFixture(t, h, 200, `{"success":true,"hostname":"site.test"}`)
			submit, page := captchaSubmission(t, h)
			if !strings.Contains(page.Body.String(), h.Captcha.SiteKey) || !strings.Contains(page.Body.String(), h.runtime.captcha.provider.script) || strings.Contains(page.Body.String(), h.Captcha.SecretKey) || strings.Contains(page.Body.String(), h.Captcha.CookieSecret) {
				t.Fatal("CAPTCHA widget missing or a private credential was exposed")
			}
			if !strings.Contains(page.Header().Get("Content-Security-Policy"), "'nonce-") || page.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("CAPTCHA page lacks CSP or cache protection")
			}
			result, called := execute(t, h, submit)
			if called || result.Code != 303 || result.Header().Get("Location") != "/original?q=1&q=2" || providerCalls.Load() != 1 {
				t.Fatalf("proof submission status=%d next=%t provider_calls=%d", result.Code, called, providerCalls.Load())
			}
			var grant *http.Cookie
			for _, cookie := range result.Result().Cookies() {
				if cookie.Name == h.runtime.captcha.cookieName {
					grant = cookie
				}
			}
			if grant == nil || !grant.HttpOnly || !grant.Secure || grant.SameSite != http.SameSiteLaxMode || grant.Domain != "" || grant.Path != "/" || grant.MaxAge != 3600 {
				t.Fatal("CAPTCHA grant is missing host-only/expiry/security attributes")
			}
			for _, tc := range []struct {
				path string
				want int
				next bool
			}{
				{"/original", 201, true}, {"/ban", 429, false}, {"/native", 200, false}, {"/error", 503, false},
			} {
				r := incoming("PATCH", "https://site.test"+tc.path, "complete original body")
				r.AddCookie(grant)
				w, next := execute(t, h, r)
				if next != tc.next || w.Code != tc.want || (next && w.Body.String() != "complete original body") {
					t.Fatalf("grant changed WAF/Bot enforcement for %s: status=%d next=%t", tc.path, w.Code, next)
				}
			}
			if inspections.Load() != 6 {
				t.Fatalf("CAPTCHA grant bypassed inspection: inspections=%d", inspections.Load())
			}
			t.Log("page, provider verification, secure grant and body-preserving continuation passed; native bans/challenges/errors stayed terminal")
		})
	}
}

func TestCaptchaConfiguration(t *testing.T) {
	base := strings.Replace(configFixture, " waf on", " captcha_provider turnstile\n captcha_site_key fixture-site\n captcha_secret_key fixture-secret\n captcha_cookie_secret "+strings.Repeat("k", 32)+"\n captcha_ttl 30m\n captcha_path /protected/captcha\n waf on", 1)
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(base)); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Handler
	if err = json.Unmarshal(data, &decoded); err != nil || decoded.Validate() != nil || decoded.Captcha.Path != "/protected/captcha" || decoded.Captcha.TTL != caddy.Duration(30*time.Minute) {
		t.Fatal("CAPTCHA configuration did not round-trip through Caddyfile and JSON")
	}
	for _, edit := range []struct {
		name   string
		change func(*CaptchaConfig)
	}{
		{"provider", func(c *CaptchaConfig) { c.Provider = "secret-invalid" }},
		{"site_key", func(c *CaptchaConfig) { c.SiteKey = "" }},
		{"secret_key", func(c *CaptchaConfig) { c.SecretKey = "" }},
		{"cookie_secret", func(c *CaptchaConfig) { c.CookieSecret = "short" }},
		{"blank_secret", func(c *CaptchaConfig) { c.CookieSecret = strings.Repeat(" ", 32) }},
		{"ttl", func(c *CaptchaConfig) { c.TTL = caddy.Duration(time.Millisecond) }},
	} {
		t.Run(edit.name, func(t *testing.T) {
			c := *h.Captcha
			edit.change(&c)
			candidate := h
			candidate.Captcha = &c
			if err := candidate.Validate(); err == nil || strings.Contains(err.Error(), "secret-invalid") {
				t.Fatal("invalid CAPTCHA settings accepted or disclosed")
			}
		})
	}
	for _, path := range []string{"/", "//evil.test", "https://evil.test/", "/%2f/evil", "/a%2fb", "/\\evil.test", "/submit?secret=1", "/submit#fragment", challengePrefix + "submit", "%"} {
		c := *h.Captcha
		c.Path = path
		if c.validate() == nil {
			t.Errorf("invalid CAPTCHA endpoint accepted: %q", path)
		}
	}
	broken := strings.Replace(base, "captcha_ttl 30m", "captcha_ttl secret-invalid", 1)
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(broken)); err == nil || strings.Contains(err.Error(), "secret-invalid") {
		t.Fatal("invalid CAPTCHA duration accepted or disclosed")
	}
}

func TestCaptchaProviderFailuresNeverGrant(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"rejected", 200, `{"success":false}`}, {"hostname", 200, `{"success":true,"hostname":"other.test"}`},
		{"missing_hostname", 200, `{"success":true}`}, {"malformed", 200, "{"}, {"server", 500, "null"},
		{"redirect", 307, ""}, {"oversized", 200, strings.Repeat("x", 129<<10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := captchaFixture(t, "turnstile", func(h *Handler) { h.FailureAction = "passthrough" })
			calls := providerFixture(t, h, tc.status, tc.body)
			r, _ := captchaSubmission(t, h)
			w, called := execute(t, h, r)
			if called || w.Code != 403 || len(w.Result().Cookies()) != 0 || calls.Load() != 1 {
				t.Fatal("provider failure granted access/cookie or reached origin")
			}
		})
	}
}

func TestCaptchaInvalidSubmissionsAreTerminal(t *testing.T) {
	for _, which := range []string{"method", "content_type", "bad_form", "missing_proof", "duplicate_proof", "forged_ticket", "missing_nonce", "wrong_nonce", "expired", "wrong_host", "wrong_ip", "unknown_path", "engine_ban", "engine_challenge", "engine_error"} {
		t.Run(which, func(t *testing.T) {
			h, _ := captchaFixture(t, "turnstile", func(h *Handler) { h.FailureAction = "passthrough" })
			calls := providerFixture(t, h, 200, `{"success":true,"hostname":"site.test"}`)
			r, _ := captchaSubmission(t, h)
			form, _ := url.ParseQuery(readBody(t, r))
			switch which {
			case "method":
				r.Method = "GET"
			case "content_type":
				r.Header.Set("Content-Type", "application/json")
			case "bad_form":
				form = url.Values{"ticket": {"%"}}
				r.Body = io.NopCloser(strings.NewReader("ticket=%"))
				r.ContentLength = int64(len("ticket=%"))
			case "missing_proof":
				form.Del(h.runtime.captcha.provider.field)
			case "duplicate_proof":
				form.Add(h.runtime.captcha.provider.field, "duplicate")
			case "forged_ticket":
				form.Set("ticket", "forged.signature")
			case "missing_nonce":
				r.Header.Del("Cookie")
			case "wrong_nonce":
				r.Header.Set("Cookie", h.runtime.captcha.cookieName+"_csrf=wrong")
			case "expired":
				form.Set("ticket", h.signCaptcha(r, "ticket", captchaClaims{Expires: time.Now().Add(-time.Second).Unix(), Nonce: singleCaptchaCookie(r, h.runtime.captcha.cookieName+"_csrf")}))
			case "wrong_host":
				r.Host = "other.test"
			case "wrong_ip":
				r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: "192.0.2.9"}))
			case "unknown_path":
				r.URL.Path = captchaPrefix + "unknown"
			case "engine_ban", "engine_challenge", "engine_error":
				h.runtime.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
					_ = req.Body.Close()
					status, body := 403, `{"action":"ban"}`
					if which == "engine_challenge" {
						body = `{"action":"challenge","user_body_content":"native-bot-page"}`
					}
					if which == "engine_error" {
						status, body = 500, "null"
					}
					return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})
			}
			if which != "bad_form" {
				data := form.Encode()
				r.Body, r.ContentLength = io.NopCloser(strings.NewReader(data)), int64(len(data))
			}
			w, called := execute(t, h, r)
			if called || w.Code == 303 || len(w.Result().Cookies()) != 0 || calls.Load() != 0 {
				t.Fatalf("invalid submission %s granted access: status=%d next=%t", which, w.Code, called)
			}
		})
	}
}

func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCaptchaGrantsCannotCrossTrustBoundaries(t *testing.T) {
	h, _ := captchaFixture(t, "turnstile")
	request := incoming("GET", "https://site.test/path", "")
	valid := h.signCaptcha(request, "grant", captchaClaims{Expires: time.Now().Add(time.Hour).Unix()})
	for _, which := range []string{"valid", "host", "ip", "endpoint", "api_key", "secret", "ticket_as_grant", "expired", "signature", "malformed", "missing", "duplicate", "oversized"} {
		t.Run(which, func(t *testing.T) {
			r := incoming("GET", "https://site.test/path", "")
			token := valid
			scoped := *h
			config := *h.Captcha
			scoped.Captcha = &config
			switch which {
			case "host":
				r.Host = "other.test"
			case "ip":
				r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: "192.0.2.9"}))
			case "endpoint":
				scoped.Endpoint += "different-profile"
			case "api_key":
				scoped.APIKey = "rotated-key"
			case "secret":
				scoped.Captcha.CookieSecret = strings.Repeat("other-key", 8)
			case "ticket_as_grant":
				token = h.signCaptcha(r, "ticket", captchaClaims{Expires: time.Now().Add(time.Hour).Unix()})
			case "expired":
				token = h.signCaptcha(r, "grant", captchaClaims{Expires: time.Now().Add(-time.Second).Unix()})
			case "signature":
				token += "!"
			case "malformed":
				token = "no-signature"
			case "missing":
				token = ""
			case "duplicate":
				r.AddCookie(&http.Cookie{Name: h.runtime.captcha.cookieName, Value: token})
			case "oversized":
				token = strings.Repeat("x", int(h.MaxResponseBytes)+1)
			}
			r.AddCookie(&http.Cookie{Name: h.runtime.captcha.cookieName, Value: token})
			if scoped.validCaptchaGrant(r) != (which == "valid") {
				t.Fatal("CAPTCHA grant crossed its trust boundary")
			}
		})
	}
}

func TestCaptchaRenderingAndReturnPaths(t *testing.T) {
	for _, target := range []string{"//evil.test", "/%2fevil.test", "/\\evil.test", "https://evil.test/", "%"} {
		if safeCaptchaReturn(target) != "/" {
			t.Fatalf("unsafe return accepted: %q", target)
		}
	}
	for _, method := range []string{"GET", "HEAD"} {
		h, _ := captchaFixture(t, "turnstile", func(h *Handler) {
			h.Bot = false
			h.Captcha.Path = "/protected/captcha"
			h.Captcha.TTL = caddy.Duration(10 * time.Minute)
		})
		r := incoming(method, "https://site.test/original", "")
		w := httptest.NewRecorder()
		w.Header().Set("Content-Security-Policy", "old-policy")
		if err := h.renderCaptcha(w, r, 0); err != nil || w.Code != 200 || (method == "HEAD" && w.Body.Len() != 0) || strings.Contains(w.Header().Get("Content-Security-Policy"), "old-policy") {
			t.Fatal("CAPTCHA status/HEAD/CSP handling failed")
		}
		if h.runtime.captcha.submitPath != "/protected/captcha" || h.runtime.captcha.ttl != 10*time.Minute {
			t.Fatal("custom CAPTCHA endpoint or TTL lost")
		}
	}
	h, _ := captchaFixture(t, "turnstile")
	r := incoming("GET", "https://site.test/original", "")
	for _, status := range []int{101, 204, 205, 304, 600} {
		w := httptest.NewRecorder()
		if err := h.renderCaptcha(w, r, status); err != nil || w.Code != 403 || len(w.Result().Cookies()) != 0 {
			t.Fatal("invalid CAPTCHA status was served")
		}
	}
	h.MaxResponseBytes = 64
	w, called := execute(t, h, r)
	if called || w.Code != 403 || len(w.Result().Cookies()) != 0 {
		t.Fatal("oversized CAPTCHA page was served")
	}
	h.MaxResponseBytes = 128 << 10
	if err := h.renderCaptcha(failedWriter{make(http.Header)}, r, 200); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("CAPTCHA write error lost: %v", err)
	}
	transport := h.runtime.captcha.client.Transport.(*http.Transport)
	if transport.Proxy != nil || (transport.TLSClientConfig != nil && (transport.TLSClientConfig.RootCAs != nil || transport.TLSClientConfig.InsecureSkipVerify)) {
		t.Fatal("public CAPTCHA verification inherited an environment proxy or private AppSec CA")
	}
	if err := h.runtime.captcha.client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatal("provider redirects are enabled")
	}
}

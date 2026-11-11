package appsec

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const captchaPrefix = "/trueops-internal/captcha/"

// CaptchaConfig configures classic provider-backed CAPTCHA remediation.
// It is independent of CrowdSec's native Bot Detection challenge protocol.
type CaptchaConfig struct {
	Provider     string         `json:"provider"`
	SiteKey      string         `json:"site_key"`
	SecretKey    string         `json:"secret_key"`
	CookieSecret string         `json:"cookie_secret"`
	TTL          caddy.Duration `json:"ttl,omitempty"`
	Path         string         `json:"path,omitempty"`
}

type captchaProvider struct{ script, verify, widget, field, origins string }

func providerFor(name string) (captchaProvider, bool) {
	switch name {
	case "turnstile":
		return captchaProvider{"https://challenges.cloudflare.com/turnstile/v0/api.js", "https://challenges.cloudflare.com/turnstile/v0/siteverify", "cf-turnstile", "cf-turnstile-response", "https://challenges.cloudflare.com"}, true
	case "hcaptcha":
		return captchaProvider{"https://js.hcaptcha.com/1/api.js", "https://api.hcaptcha.com/siteverify", "h-captcha", "h-captcha-response", "https://hcaptcha.com https://*.hcaptcha.com"}, true
	case "recaptcha":
		return captchaProvider{"https://www.google.com/recaptcha/api.js", "https://www.google.com/recaptcha/api/siteverify", "g-recaptcha", "g-recaptcha-response", "https://www.google.com https://www.gstatic.com https://www.recaptcha.net"}, true
	}
	return captchaProvider{}, false
}

func (c *CaptchaConfig) validate() error {
	if _, ok := providerFor(c.Provider); !ok {
		return errors.New("appsec: captcha_provider must be turnstile, hcaptcha or recaptcha")
	}
	if strings.TrimSpace(c.SiteKey) == "" || strings.TrimSpace(c.SecretKey) == "" || len(c.CookieSecret) < 32 || strings.TrimSpace(c.CookieSecret) == "" {
		return errors.New("appsec: CAPTCHA requires site/secret keys and a cookie secret of at least 32 bytes")
	}
	if c.TTL != 0 && c.TTL < caddy.Duration(time.Second) {
		return errors.New("appsec: captcha_ttl must be at least one second")
	}
	if c.Path != "" {
		path, err := url.ParseRequestURI(c.Path)
		if err != nil || path.Path != c.Path || safeCaptchaReturn(c.Path) != c.Path || c.Path == "/" || strings.ContainsAny(c.Path, "?#") || isChallengePath(c.Path) {
			return errors.New("appsec: captcha_path must be a dedicated local path outside native challenge routes")
		}
	}
	return nil
}

func (c *CaptchaConfig) set(key, value string) error {
	switch key {
	case "captcha_provider":
		c.Provider = value
	case "captcha_site_key":
		c.SiteKey = value
	case "captcha_secret_key":
		c.SecretKey = value
	case "captcha_cookie_secret":
		c.CookieSecret = value
	case "captcha_path":
		c.Path = value
	case "captcha_ttl":
		duration, err := caddy.ParseDuration(value)
		if err != nil {
			return err
		}
		c.TTL = caddy.Duration(duration)
	}
	return nil
}

type captchaRuntime struct {
	provider   captchaProvider
	client     *http.Client
	page       *template.Template
	cookieName string
	submitPath string
	ttl        time.Duration
}

func (h *Handler) prepareCaptcha() *captchaRuntime {
	provider, _ := providerFor(h.Captcha.Provider) // Validate checked the provider.
	id := sha256.Sum256([]byte(h.Endpoint + "\x00" + h.Captcha.Provider + "\x00" + h.Captcha.SiteKey + "\x00" + h.Captcha.CookieSecret))
	rt := &captchaRuntime{provider: provider, client: h.baseClient(), page: template.Must(template.New("captcha").Parse(captchaPage)),
		cookieName: "trueops_captcha_" + hex.EncodeToString(id[:8]), submitPath: h.Captcha.Path, ttl: time.Duration(h.Captcha.TTL)}
	if rt.submitPath == "" {
		rt.submitPath = captchaPrefix + "submit"
	}
	if rt.ttl == 0 {
		rt.ttl = time.Hour
	}
	return rt
}

func (h *Handler) isCaptchaPath(path string) bool {
	return strings.HasPrefix(path, captchaPrefix) || (h.runtime != nil && h.runtime.captcha != nil && path == h.runtime.captcha.submitPath)
}

func (h *Handler) isRemediationPath(path string) bool {
	return isChallengePath(path) || h.isCaptchaPath(path)
}

const captchaPage = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify you're human</title>
<script nonce="{{.Nonce}}" src="{{.Script}}" async defer></script>
</head><body><main>
<h1>Verify you're human</h1><p>Complete the verification to continue.</p>
<form method="post" action="{{.Path}}">
<input type="hidden" name="ticket" value="{{.Ticket}}">
<div class="{{.Widget}}" data-sitekey="{{.SiteKey}}"></div>
<button type="submit">Continue</button>
</form></main></body></html>`

type captchaPageData struct{ Nonce, Script, Path, Ticket, Widget, SiteKey string }

type captchaPageBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *captchaPageBuffer) Write(p []byte) (int, error) {
	if int64(b.buffer.Len())+int64(len(p)) > b.limit {
		return 0, errors.New("CAPTCHA page exceeds response budget")
	}
	return b.buffer.Write(p)
}

func (h *Handler) renderCaptcha(w http.ResponseWriter, r *http.Request, status int) error {
	if h.runtime == nil || h.runtime.captcha == nil || h.isRemediationPath(r.URL.Path) {
		return h.reject(w, r, http.StatusForbidden, "captcha_unavailable")
	}
	if status == 0 {
		status = http.StatusOK
	}
	if status < 200 || status > 599 || status == 204 || status == 205 || status == 304 {
		return h.reject(w, r, http.StatusForbidden, "invalid_captcha_status")
	}
	rt := h.runtime.captcha
	// The ticket and browser nonce expire after the longest supported provider
	// token lifetime (Turnstile: five minutes). Providers enforce single use.
	nonce := rand.Text()
	ticket := h.signCaptcha(r, "ticket", captchaClaims{Expires: time.Now().Add(5 * time.Minute).Unix(), Nonce: nonce, Return: safeCaptchaReturn(r.URL.RequestURI())})
	data := captchaPageData{rand.Text(), rt.provider.script, rt.submitPath, ticket, rt.provider.widget, h.Captcha.SiteKey}
	page := &captchaPageBuffer{limit: h.MaxResponseBytes}
	if err := rt.page.Execute(page, data); err != nil {
		return h.reject(w, r, http.StatusForbidden, "captcha_render_failure")
	}
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+data.Nonce+"' 'strict-dynamic' "+rt.provider.origins+"; frame-src "+rt.provider.origins+"; connect-src "+rt.provider.origins+"; style-src 'unsafe-inline' "+rt.provider.origins+"; img-src data: "+rt.provider.origins+"; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.captchaCookie(w, r, rt.cookieName+"_csrf", nonce, rt.submitPath, 5*time.Minute)
	h.trace("captcha", status)
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return nil
	}
	_, err := w.Write(page.buffer.Bytes())
	return err
}

func (h *Handler) submitCaptcha(w http.ResponseWriter, r *http.Request, body []byte) error {
	if h.runtime.captcha == nil || r.URL.Path != h.runtime.captcha.submitPath {
		return h.reject(w, r, http.StatusNotFound, "unknown_captcha_path")
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return h.reject(w, r, http.StatusMethodNotAllowed, "captcha_method")
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		return h.reject(w, r, http.StatusUnsupportedMediaType, "captcha_form")
	}
	form, err := url.ParseQuery(string(body))
	rt := h.runtime.captcha
	if err != nil || len(form["ticket"]) != 1 || len(form[rt.provider.field]) != 1 || form.Get(rt.provider.field) == "" {
		return h.reject(w, r, http.StatusBadRequest, "captcha_form")
	}
	claims, ok := h.checkCaptcha(r, "ticket", form.Get("ticket"))
	csrf := singleCaptchaCookie(r, rt.cookieName+"_csrf")
	if !ok || csrf == "" || claims.Nonce == "" || claims.Nonce != csrf {
		return h.reject(w, r, http.StatusForbidden, "captcha_ticket")
	}
	if !h.verifyCaptcha(r, form.Get(rt.provider.field)) || r.Context().Err() != nil {
		return h.reject(w, r, http.StatusForbidden, "captcha_verification_failure")
	}
	grant := h.signCaptcha(r, "grant", captchaClaims{Expires: time.Now().Add(rt.ttl).Unix()})
	h.captchaCookie(w, r, rt.cookieName, grant, "/", rt.ttl)
	h.captchaCookie(w, r, rt.cookieName+"_csrf", "", rt.submitPath, -time.Second)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	h.trace("captcha_verified", http.StatusSeeOther)
	// Never replay the original POST or send a CAPTCHA token to the application.
	http.Redirect(w, r, safeCaptchaReturn(claims.Return), http.StatusSeeOther)
	return nil
}

func (h *Handler) verifyCaptcha(r *http.Request, token string) bool {
	rt := h.runtime.captcha
	ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	form := url.Values{"secret": {h.Captcha.SecretKey}, "response": {token}, "remoteip": {ip}}
	if h.Captcha.Provider == "hcaptcha" {
		form.Set("sitekey", h.Captcha.SiteKey)
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.Timeout))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rt.provider.verify, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "trueops-appsec")
	resp, err := rt.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, h.MaxResponseBytes+1))
	if err != nil || int64(len(data)) > h.MaxResponseBytes {
		return false
	}
	var result struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
	}
	return json.Unmarshal(data, &result) == nil && result.Success && captchaHostname(result.Hostname) == captchaHostname(r.Host)
}

package appsec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type captchaClaims struct {
	Expires int64  `json:"exp"`
	Nonce   string `json:"nonce,omitempty"`
	Return  string `json:"return,omitempty"`
}

func captchaHostname(host string) string {
	u := &url.URL{Host: host}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

func safeCaptchaReturn(target string) string {
	u, err := url.ParseRequestURI(target)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, "\\") {
		return "/"
	}
	return target
}

func (h *Handler) captchaMAC(r *http.Request, purpose, payload string) []byte {
	mac := hmac.New(sha256.New, []byte(h.Captcha.CookieSecret))
	ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	for _, value := range []string{purpose, strings.ToLower(r.Host), ip, h.Endpoint, h.APIKey, h.Captcha.Provider, h.Captcha.SiteKey, h.runtime.captcha.submitPath, payload} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write([]byte(value))
	}
	return mac.Sum(nil)
}

func (h *Handler) signCaptcha(r *http.Request, purpose string, claims captchaClaims) string {
	data, _ := json.Marshal(claims) // This struct contains only strings and an integer.
	payload := base64.RawURLEncoding.EncodeToString(data)
	return payload + "." + base64.RawURLEncoding.EncodeToString(h.captchaMAC(r, purpose, payload))
}

func (h *Handler) checkCaptcha(r *http.Request, purpose, token string) (captchaClaims, bool) {
	var claims captchaClaims
	if int64(len(token)) > h.MaxResponseBytes {
		return claims, false
	}
	payload, signature, ok := strings.Cut(token, ".")
	if !ok {
		return claims, false
	}
	provided, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !hmac.Equal(provided, h.captchaMAC(r, purpose, payload)) {
		return claims, false
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(data, &claims) != nil || claims.Expires <= time.Now().Unix() {
		return captchaClaims{}, false
	}
	return claims, true
}

func singleCaptchaCookie(r *http.Request, name string) string {
	cookies := r.CookiesNamed(name)
	if len(cookies) != 1 {
		return ""
	}
	return cookies[0].Value
}

func (h *Handler) validCaptchaGrant(r *http.Request) bool {
	if h.runtime.captcha == nil {
		return false
	}
	_, ok := h.checkCaptcha(r, "grant", singleCaptchaCookie(r, h.runtime.captcha.cookieName))
	return ok
}

func (h *Handler) captchaCookie(w http.ResponseWriter, r *http.Request, name, value, path string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ttl / time.Second), Expires: time.Now().Add(ttl)})
}

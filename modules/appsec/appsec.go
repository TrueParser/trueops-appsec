// Package appsec integrates CrowdSec's native AppSec protocol into Caddy.
package appsec

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("trueops_appsec", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m Handler
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return &m, err
	})
}

// Handler enforces the native profile bound to Endpoint. Host/path selection and
// policy exclusions belong to Caddy routes. The external engine owns detection.
type Handler struct {
	WAF              bool           `json:"waf,omitempty"`
	Bot              bool           `json:"bot,omitempty"`
	Endpoint         string         `json:"endpoint,omitempty"`
	APIKey           string         `json:"api_key,omitempty"`
	Timeout          caddy.Duration `json:"timeout,omitempty"`
	MaxBodyBytes     int64          `json:"max_body_bytes,omitempty"`
	MaxResponseBytes int64          `json:"max_response_bytes,omitempty"`
	MaxInFlight      int            `json:"max_in_flight,omitempty"`
	CAFile           string         `json:"ca_file,omitempty"`
	FailureAction    string         `json:"failure_action,omitempty"`

	runtime *runtime
}

type runtime struct {
	client   *http.Client
	endpoint *url.URL
	slots    chan struct{}
	logger   *zap.Logger
	retired  atomic.Bool
}

// CaddyModule registers a distinct module ID alongside other AppSec plugins.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.trueops_appsec",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision prepares configuration once; it never contacts the engine.
func (h *Handler) Provision(ctx caddy.Context) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if !h.WAF && !h.Bot {
		return nil
	}
	client, err := h.newClient(x509.SystemCertPool)
	if err != nil {
		return err
	}
	endpoint, _ := url.Parse(h.Endpoint) // already checked by Validate
	h.runtime = &runtime{
		client:   client,
		endpoint: endpoint,
		slots:    make(chan struct{}, h.MaxInFlight),
		logger:   ctx.Logger(),
	}
	return nil
}

// Cleanup retires idle connections without canceling active request contexts.
func (h *Handler) Cleanup() error {
	if h.runtime != nil {
		h.runtime.retired.Store(true)
		h.runtime.client.CloseIdleConnections()
	}
	return nil
}

// ServeHTTP continues after native allow or an explicitly configured failure passthrough.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Keep this first: no context, logging, body, challenge or runtime work off.
	if !h.WAF && !h.Bot {
		return next.ServeHTTP(w, r)
	}
	rt := h.runtime
	if rt == nil {
		return h.reject(w, r, http.StatusServiceUnavailable, "not_provisioned")
	}
	select {
	case rt.slots <- struct{}{}:
	default:
		return h.reject(w, r, http.StatusServiceUnavailable, "capacity")
	}
	held := true
	defer func() {
		if held {
			<-rt.slots
		}
		// Requests already in Caddy's old chain can enter after Cleanup. Their
		// final use must also close idle connections created after retirement.
		if rt.retired.Load() {
			rt.client.CloseIdleConnections()
		}
	}()
	if r.Context().Err() != nil {
		return h.reject(w, r, http.StatusServiceUnavailable, "canceled")
	}
	body, status := h.capture(r)
	if status != 0 {
		return h.reject(w, r, status, "request_body")
	}
	decision, status, engineFailure := h.inspect(r, body)
	if r.Context().Err() != nil {
		return h.reject(w, r, http.StatusServiceUnavailable, "canceled")
	}
	if status != 0 {
		if !engineFailure || h.FailureAction != "passthrough" || isChallengePath(r.URL.Path) {
			return h.reject(w, r, status, "engine_failure")
		}
		h.trace("engine_failure_passthrough", status)
	} else {
		if decision.Action != "allow" {
			return h.remediate(w, r, decision)
		}
		if isChallengePath(r.URL.Path) {
			return h.reject(w, r, http.StatusNotFound, "unknown_challenge_path")
		}
		h.trace("allow", 0)
	}
	if len(body) == 0 {
		// Body-free streams/downloads need no capture reservation downstream.
		<-rt.slots
		held = false
	}
	return next.ServeHTTP(w, r)
}

func (h *Handler) trace(result string, status int) {
	if h.runtime == nil || h.runtime.logger == nil {
		return
	}
	if entry := h.runtime.logger.Check(zap.DebugLevel, "AppSec result"); entry != nil {
		entry.Write(zap.String("result", result), zap.Int("status", status))
	}
}

func (h *Handler) reject(w http.ResponseWriter, _ *http.Request, status int, reason string) error {
	h.trace(reason, status)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
	return nil
}

var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

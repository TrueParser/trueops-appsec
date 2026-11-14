package upstreampool

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// Admin extends Caddy's existing Admin listener and its trust/permission checks.
type Admin struct{}

func (Admin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "admin.api.trueops_pools", New: func() caddy.Module { return new(Admin) }}
}

func (a *Admin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{{Pattern: "/upstream-pools/", Handler: a}}
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Message: "method not allowed"}
	}
	id := strings.TrimPrefix(r.URL.Path, "/upstream-pools/")
	if id == "" || strings.Contains(id, "/") {
		return caddy.APIError{HTTPStatus: http.StatusNotFound, Message: "pool not found"}
	}
	app, p, err := configuredPool(caddy.ActiveContext(), id)
	if err != nil {
		return caddy.APIError{HTTPStatus: http.StatusNotFound, Message: "pool not configured"}
	}
	var status Status
	if r.Method == http.MethodPut {
		// A control-message bound, not a limit on proxied request bodies.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var u Update
		if err = dec.Decode(&u); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return caddy.APIError{HTTPStatus: http.StatusRequestEntityTooLarge, Message: "pool update exceeds control-message limit"}
			}
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Message: "invalid pool update"}
		}
		if err = dec.Decode(new(any)); err != io.EOF {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return caddy.APIError{HTTPStatus: http.StatusRequestEntityTooLarge, Message: "pool update exceeds control-message limit"}
			}
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Message: "expected one pool update"}
		}
		status, err = p.replace(r.Context(), p.instance, u)
		if err != nil {
			code := http.StatusBadRequest
			if errors.Is(err, errConflict) {
				code = http.StatusConflict
			}
			if errors.Is(err, errStorage) {
				code = http.StatusServiceUnavailable
			}
			return caddy.APIError{HTTPStatus: code, Message: err.Error()}
		}
		app.logger.Debug("pool update applied", zap.String("pool", id), zap.Uint64("revision", status.Revision),
			zap.Int("targets", len(status.Targets)), zap.Int("draining_generations", len(status.Draining)))
	} else {
		status = p.status(p.instance)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return json.NewEncoder(w).Encode(status)
}

var (
	_ caddy.AdminRouter  = (*Admin)(nil)
	_ caddy.AdminHandler = (*Admin)(nil)
)

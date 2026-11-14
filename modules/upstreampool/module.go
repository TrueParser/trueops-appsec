package upstreampool

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
	caddy.RegisterModule(Handler{})
	caddy.RegisterModule(Source{})
	caddy.RegisterModule(Admin{})
}

// App owns pools for exactly one Caddy configuration. It starts no workers.
type App struct {
	StateID string          `json:"state_id"`
	Pools   map[string]Spec `json:"pools"`

	pools  map[string]*pool
	logger *zap.Logger
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "trueops_pools", New: func() caddy.Module { return new(App) }}
}

func (a *App) Provision(ctx caddy.Context) error {
	if strings.TrimSpace(a.StateID) == "" {
		return fmt.Errorf("state_id must identify this Caddy instance's durable pools")
	}
	a.logger = ctx.Logger()
	a.pools = make(map[string]*pool, len(a.Pools))
	for name, spec := range a.Pools {
		if name == "" || strings.ContainsAny(name, "/?#%\\") {
			return fmt.Errorf("pool identifier must be a nonempty URL segment")
		}
		if err := validateSpec(spec); err != nil {
			return fmt.Errorf("pool %q: %w", name, err)
		}
		key := runtimeKey{a.StateID, name}
		value, _, err := poolRuntimes.LoadOrNew(key, func() (caddy.Destructor, error) {
			return restorePool(ctx, ctx.Storage(), a.StateID, name, spec, a.logger)
		})
		if err != nil {
			return fmt.Errorf("pool %q: %w", name, err)
		}
		ctx.OnCancel(func() { _, _ = poolRuntimes.Delete(key) })
		p := value.(*pool)
		if p.bootstrap != specFingerprint(spec) {
			return fmt.Errorf("pool %q: configured bootstrap changed; use the pool API or a new state_id", name)
		}
		a.pools[name] = p
	}
	return nil
}

func (*App) Start() error { return nil }
func (*App) Stop() error  { return nil }

func configuredPool(ctx caddy.Context, id string) (*App, *pool, error) {
	v, err := ctx.AppIfConfigured("trueops_pools")
	if err != nil {
		return nil, nil, err
	}
	a := v.(*App)
	p, ok := a.pools[id]
	if !ok {
		return nil, nil, fmt.Errorf("pool is not configured")
	}
	return a, p, nil
}

// Handler leases one generation through the entire downstream handler call.
type Handler struct {
	Pool string `json:"pool"`
	p    *pool
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.trueops_pool", New: func() caddy.Module { return new(Handler) }}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	_, p, err := configuredPool(ctx, h.Pool)
	h.p = p
	return err
}

type leaseKey struct{}
type lease struct {
	pool *pool
	gen  *generation
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	g := h.p.acquire()
	defer h.p.release(g)
	l := &lease{pool: h.p, gen: g}
	return next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), leaseKey{}, l)))
}

// Source returns fresh native upstream objects because Caddy provisions them.
// The immutable address set is taken from the request lease, including retries.
type Source struct {
	Pool string `json:"pool"`
	p    *pool
}

func (Source) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.reverse_proxy.upstreams.trueops_pool", New: func() caddy.Module { return new(Source) }}
}

func (s *Source) Provision(ctx caddy.Context) error {
	_, p, err := configuredPool(ctx, s.Pool)
	s.p = p
	return err
}

func (s *Source) GetUpstreams(r *http.Request) ([]*reverseproxy.Upstream, error) {
	l, ok := r.Context().Value(leaseKey{}).(*lease)
	if !ok || l.pool != s.p {
		// Empty success deliberately prevents Caddy's static-error fallback.
		return []*reverseproxy.Upstream{}, nil
	}
	u := make([]*reverseproxy.Upstream, len(l.gen.spec.Targets))
	for i, addr := range l.gen.spec.Targets {
		u[i] = &reverseproxy.Upstream{Dial: addr}
	}
	return u, nil
}

var (
	_ caddy.App                   = (*App)(nil)
	_ caddy.Provisioner           = (*App)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ reverseproxy.UpstreamSource = (*Source)(nil)
	_ caddy.Provisioner           = (*Source)(nil)
)

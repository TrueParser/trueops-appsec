// Package upstreampool provides revisioned pool changes without HTTP reloads.
package upstreampool

import (
	"context"
	"crypto/rand"
	"errors"
	"math"
	"slices"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

// Spec is an immutable, complete set of operator-selected upstream addresses.
type Spec struct {
	Revision uint64   `json:"revision"`
	Targets  []string `json:"targets"`
}

// Update compares both the running configuration instance and pool revision.
type Update struct {
	ExpectedInstance string `json:"expected_instance"`
	ExpectedRevision uint64 `json:"expected_revision"`
	Spec
}

type generation struct {
	spec   Spec
	active int64
}

type pool struct {
	writeMu   sync.Mutex
	mu        sync.Mutex
	instance  string
	bootstrap string
	state     *stateStore
	current   *generation
	retiring  map[uint64]*generation
	last      Update
}

// GenerationStatus counts admitted requests, including work not yet dialed.
type GenerationStatus struct {
	Revision uint64 `json:"revision"`
	Active   int64  `json:"active_requests"`
}

// Status is runtime evidence, separate from Caddy's unchanged bootstrap config.
type Status struct {
	Instance string `json:"instance"`
	Spec
	Active   int64              `json:"active_requests"`
	Draining []GenerationStatus `json:"draining"`
}

var errConflict = errors.New("pool instance or revision conflict")

func validateSpec(s Spec) error {
	if s.Revision == 0 || len(s.Targets) == 0 {
		return errors.New("pool requires a positive revision and nonempty targets")
	}
	seen := make(map[string]bool, len(s.Targets))
	for _, target := range s.Targets {
		if strings.ContainsAny(target, "{}\r\n") || seen[target] {
			return errors.New("pool targets must be distinct literal network addresses")
		}
		addr, err := caddy.ParseNetworkAddress(target)
		if err != nil || addr.Host == "" || (!addr.IsUnixNetwork() &&
			(addr.PortRangeSize() != 1 || addr.StartPort == 0 ||
				(addr.Network != "tcp" && addr.Network != "tcp4" && addr.Network != "tcp6"))) {
			return errors.New("pool requires single TCP sockets or Unix sockets")
		}
		seen[target] = true
	}
	return nil
}

func newPool(s Spec) *pool {
	s.Targets = slices.Clone(s.Targets)
	return &pool{instance: rand.Text(), current: &generation{spec: s}, retiring: make(map[uint64]*generation)}
}

func (p *pool) acquire() *generation {
	p.mu.Lock()
	defer p.mu.Unlock()
	g := p.current
	g.active++
	return g
}

func (p *pool) release(g *generation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g.active--
	if g != p.current && g.active == 0 {
		delete(p.retiring, g.spec.Revision)
	}
}

func (p *pool) replace(ctx context.Context, instance string, u Update) (Status, error) {
	if err := validateSpec(u.Spec); err != nil {
		return Status{}, err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	if u.ExpectedInstance != instance {
		p.mu.Unlock()
		return Status{}, errConflict
	}
	if u.ExpectedRevision == p.last.ExpectedRevision && u.Revision == p.last.Revision &&
		slices.Equal(u.Targets, p.last.Targets) {
		status := p.statusLocked(instance)
		p.mu.Unlock()
		return status, nil
	}
	if p.current.spec.Revision == math.MaxUint64 || u.ExpectedRevision != p.current.spec.Revision ||
		u.Revision != u.ExpectedRevision+1 {
		p.mu.Unlock()
		return Status{}, errConflict
	}
	previous := p.current.spec
	p.mu.Unlock()
	if p.state != nil {
		if err := p.state.save(ctx, p.bootstrap, previous, u.Spec); err != nil {
			return Status{}, err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.current
	if old.active > 0 {
		p.retiring[old.spec.Revision] = old
	}
	u.Targets = slices.Clone(u.Targets)
	p.current = &generation{spec: u.Spec}
	p.last = u
	return p.statusLocked(instance), nil
}

// Destruct releases the native usage-pool entry; request leases retain their
// own references until downstream work ends. The pool owns no workers or sockets.
func (*pool) Destruct() error { return nil }

func (p *pool) status(instance string) Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.statusLocked(instance)
}

func (p *pool) statusLocked(instance string) Status {
	s := Status{Instance: instance, Spec: Spec{Revision: p.current.spec.Revision,
		Targets: slices.Clone(p.current.spec.Targets)}, Active: p.current.active,
		Draining: make([]GenerationStatus, 0, len(p.retiring))}
	for _, g := range p.retiring {
		s.Draining = append(s.Draining, GenerationStatus{Revision: g.spec.Revision, Active: g.active})
	}
	slices.SortFunc(s.Draining, func(a, b GenerationStatus) int {
		if a.Revision < b.Revision {
			return -1
		}
		if a.Revision > b.Revision {
			return 1
		}
		return 0
	})
	return s
}

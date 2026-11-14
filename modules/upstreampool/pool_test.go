package upstreampool

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestRequestPinsPoolBeforeDialAndAcrossRetries(t *testing.T) {
	p := newPool(Spec{Revision: 1, Targets: []string{"127.0.0.1:10001"}})
	h := Handler{Pool: "site", p: p}
	source := Source{Pool: "site", p: p}
	err := h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "https://site.test/", nil),
		caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
			u := Update{ExpectedInstance: "fixture", ExpectedRevision: 1,
				Spec: Spec{Revision: 2, Targets: []string{"127.0.0.1:10002"}}}
			status, err := p.replace(t.Context(), "fixture", u)
			if err != nil || len(status.Draining) != 1 || status.Draining[0].Active != 1 {
				t.Fatalf("pre-dial lease lost: status=%+v err=%v", status, err)
			}
			for range 3 {
				upstreams, err := source.GetUpstreams(r.Clone(r.Context()))
				if err != nil || len(upstreams) != 1 || upstreams[0].Dial != "127.0.0.1:10001" {
					t.Fatalf("retry changed generation: %v %v", upstreams, err)
				}
				upstreams[0].Dial = "mutated-by-consumer"
			}
			return errors.New("downstream fixture failure")
		}))
	if err == nil || len(p.status("fixture").Draining) != 0 {
		t.Fatal("failed request did not release its exact generation")
	}
	if got := p.acquire(); got.spec.Revision != 2 {
		t.Fatal("new request did not select new generation")
	} else {
		p.release(got)
	}
	t.Log("old pre-dial request and retries stayed on V1; new admissions selected V2; error released lease")
}

func TestPoolUpdatesAreExactAndConcurrent(t *testing.T) {
	for _, count := range []int{2, 3, 5, 11} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			targets := make([]string, count)
			for i := range targets {
				targets[i] = fmt.Sprintf("127.0.0.1:%d", 11000+i)
			}
			p := newPool(Spec{Revision: 1, Targets: targets})
			u := Update{ExpectedInstance: "fixture", ExpectedRevision: 1,
				Spec: Spec{Revision: 2, Targets: []string{"127.0.0.1:12000"}}}
			var successes atomic.Int64
			var wg sync.WaitGroup
			for i := range 16 {
				wg.Go(func() {
					candidate := u
					candidate.Targets = []string{fmt.Sprintf("127.0.0.1:%d", 12000+i)}
					if _, err := p.replace(t.Context(), "fixture", candidate); err == nil {
						successes.Add(1)
					} else if !errors.Is(err, errConflict) {
						t.Errorf("unexpected update error: %v", err)
					}
				})
			}
			wg.Wait()
			if successes.Load() != 1 {
				t.Fatalf("conflicting concurrent plans applied %d times", successes.Load())
			}
			u.Targets = p.status("fixture").Targets
			if _, err := p.replace(t.Context(), "fixture", u); err != nil {
				t.Fatalf("exact duplicate failed: %v", err)
			}
			u.Targets[0] = "127.0.0.1:13000"
			if slices.Equal(p.status("fixture").Targets, []string{u.Targets[0]}) {
				t.Fatal("returned projection aliases mutable pool targets")
			}
			if _, err := p.replace(t.Context(), "fixture", u); !errors.Is(err, errConflict) {
				t.Fatal("same revision with different targets was accepted")
			}
			u.ExpectedInstance = "previous-process"
			if _, err := p.replace(t.Context(), "fixture", u); !errors.Is(err, errConflict) {
				t.Fatal("previous-instance request was accepted")
			}
			t.Logf("%d-target pool: one CAS winner, exact duplicate accepted, mutation and old-instance requests rejected", count)
		})
	}
}

func TestPoolIsolationMissingLeaseAndValidation(t *testing.T) {
	p := newPool(Spec{Revision: 1, Targets: []string{"127.0.0.1:10001"}})
	other := newPool(Spec{Revision: 1, Targets: []string{"127.0.0.1:10002"}})
	source := Source{p: p}
	r := httptest.NewRequest("GET", "https://site.test/", nil)
	r.Header.Set("X-Upstream-Pool", "other")
	for _, ctx := range []context.Context{r.Context(), context.WithValue(r.Context(), leaseKey{}, &lease{pool: other, gen: other.current})} {
		upstreams, err := source.GetUpstreams(r.WithContext(ctx))
		if err != nil || len(upstreams) != 0 {
			t.Fatal("missing/cross-pool lease did not return empty success to disable static fallback")
		}
	}
	for _, targets := range [][]string{nil, {"{http.request.header.Target}:80"}, {"127.0.0.1:1000-1002"},
		{"127.0.0.1:0"}, {"https://user:password@host"}, {"udp/127.0.0.1:10001"}, {"127.0.0.1:10001", "127.0.0.1:10001"}} {
		if err := validateSpec(Spec{Revision: 1, Targets: targets}); err == nil {
			t.Errorf("invalid targets accepted: %v", targets)
		}
	}
	t.Log("public selector headers and cross-pool leases cannot select targets; literal socket validation passed")
}

func TestCancellationDoesNotReleaseExecutingWork(t *testing.T) {
	p := newPool(Spec{Revision: 1, Targets: []string{"127.0.0.1:10001"}})
	h := Handler{p: p}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://site.test/", nil).WithContext(ctx),
			caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				close(entered)
				<-finish
				return nil
			}))
	}()
	<-entered
	cancel()
	u := Update{ExpectedInstance: "fixture", ExpectedRevision: 1,
		Spec: Spec{Revision: 2, Targets: []string{"127.0.0.1:10002"}}}
	s, err := p.replace(t.Context(), "fixture", u)
	// Always release the test barrier before reporting a failure.
	close(finish)
	<-done
	if err != nil || len(s.Draining) != 1 || s.Draining[0].Active != 1 || len(p.status("fixture").Draining) != 0 {
		t.Fatalf("caller cancellation released executing work: status=%+v err=%v", s, err)
	}
	t.Log("canceled request retained its lease until downstream returned")
}

func BenchmarkPoolLease(b *testing.B) {
	p := newPool(Spec{Revision: 1, Targets: []string{"127.0.0.1:10001"}})
	h := Handler{p: p}
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	r := httptest.NewRequest("GET", "https://site.test/", nil)
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := h.ServeHTTP(w, r, next); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNativeHandlerBaseline(b *testing.B) {
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	r := httptest.NewRequest("GET", "https://site.test/", nil)
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := next.ServeHTTP(w, r); err != nil {
			b.Fatal(err)
		}
	}
}

package appsec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func BenchmarkDisabledPath(b *testing.B) {
	r := httptest.NewRequest("GET", "http://benchmark.test/", nil)
	w := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	h := &Handler{}
	b.Run("matching-handler-baseline", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := next.ServeHTTP(w, r); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("configured-both-off", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := h.ServeHTTP(w, r, next); err != nil {
				b.Fatal(err)
			}
		}
	})
}

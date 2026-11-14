package pool_test

import (
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCandidatePoolOverhead(t *testing.T) {
	f := setup(t)
	t.Log("diagnostic only: same candidate, origins and host; TLS HTTP/1.1 keepalive, concurrency=8, 2s rounds; shared-host load generator")
	for round := range 3 {
		paths := []string{"/baseline", "/echo"}
		if round%2 != 0 {
			slices.Reverse(paths)
		}
		for _, path := range paths {
			var count, failures atomic.Int64
			var mu sync.Mutex
			var all []time.Duration
			var wg sync.WaitGroup
			start := time.Now()
			deadline := start.Add(2 * time.Second)
			for range 8 {
				wg.Go(func() {
					cfg := f.client.Transport.(*http.Transport).TLSClientConfig.Clone()
					cfg.NextProtos = nil
					transport := &http.Transport{Proxy: nil, TLSClientConfig: cfg}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
					var samples []time.Duration
					for time.Now().Before(deadline) {
						requestStart := time.Now()
						e, protocol, err := request(client, f.site, path, "GET", nil)
						samples = append(samples, time.Since(requestStart))
						count.Add(1)
						if err != nil || protocol != 1 || e.Version != "v1" {
							if failures.Add(1) <= 3 {
								t.Logf("measurement request failed: %+v protocol=%d err=%v", e, protocol, err)
							}
						}
					}
					mu.Lock()
					all = append(all, samples...)
					mu.Unlock()
				})
			}
			wg.Wait()
			elapsed := time.Since(start)
			if count.Load() == 0 || failures.Load() != 0 {
				t.Fatalf("path=%s requests=%d failures=%d", path, count.Load(), failures.Load())
			}
			slices.Sort(all)
			t.Logf("round=%d path=%s requests=%d errors=%d rps=%.1f p50=%s p99=%s", round+1, path,
				count.Load(), failures.Load(), float64(count.Load())/elapsed.Seconds(), all[len(all)/2], all[len(all)*99/100])
		}
	}
}

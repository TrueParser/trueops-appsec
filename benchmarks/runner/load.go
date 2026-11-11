package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

type workload struct {
	Name, Method, Path, Cookie string
	ContentType                string
	Body                       []byte
	Static                     bool
	Challenge                  bool
}
type measurements struct {
	Requests   int64         `json:"requests"`
	Errors     int64         `json:"errors"`
	Seconds    float64       `json:"seconds"`
	Throughput float64       `json:"requests_per_second"`
	P50        float64       `json:"p50_ms"`
	P95        float64       `json:"p95_ms"`
	P99        float64       `json:"p99_ms"`
	Statuses   map[int]int64 `json:"http_statuses"`
}

func check(client *http.Client, base string, w workload) error {
	req, err := http.NewRequest(w.Method, base+w.Path, bytes.NewReader(w.Body))
	if err != nil {
		return err
	}
	req.Host = "appsec-benchmark.test"
	req.Header.Set("User-Agent", agent)
	if w.ContentType != "" {
		req.Header.Set("Content-Type", w.ContentType)
	}
	if w.Cookie != "" {
		req.Header.Set("Cookie", w.Cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if w.Challenge {
		if !expectedResponse(resp, w) || len(body) == 0 || resp.Header.Get("Content-Security-Policy") == "" {
			return fmt.Errorf("preflight %s: incomplete native browser challenge", w.Name)
		}
		return nil
	}
	want := digest(w.Body)
	if w.Static {
		want = "benchmark-static-file\n"
	}
	if resp.StatusCode != 200 || string(body) != want {
		return fmt.Errorf("preflight %s: status=%d body mismatch (challenge/deny is not origin allow)", w.Name, resp.StatusCode)
	}
	if !w.Static && (resp.Header.Get("X-Benchmark-Method") != w.Method || resp.Header.Get("X-Benchmark-Target") != w.Path || resp.Header.Get("X-Benchmark-Host") != "appsec-benchmark.test") {
		return fmt.Errorf("preflight %s: request metadata changed", w.Name)
	}
	return nil
}

func expectedResponse(resp *http.Response, w workload) bool {
	if w.Challenge {
		return (resp.StatusCode == 200 || resp.StatusCode == 307) && resp.Header.Get("X-Benchmark-Origin") == "" && strings.Contains(resp.Header.Get("Content-Type"), "text/html")
	}
	want := "owned"
	if w.Static {
		want = "owned-static"
	}
	return resp.StatusCode == 200 && resp.Header.Get("X-Benchmark-Origin") == want
}

// Use a fixed logarithmic histogram rather than retaining one sample/request.
// Buckets have ~1% resolution; the report states the precision explicitly.
func latencyBucket(d time.Duration) int {
	n := int(math.Log1p(float64(d.Microseconds())) / math.Log(1.01))
	if n > 2047 {
		return 2047
	}
	return n
}
func percentile(b []int64, p float64) float64 {
	var total int64
	for _, n := range b {
		total += n
	}
	if total == 0 {
		return 0
	}
	want := int64(math.Ceil(float64(total) * p))
	var n int64
	for i, v := range b {
		n += v
		if n >= want {
			return math.Expm1(float64(i+1)*math.Log(1.01)) / 1000
		}
	}
	return 0
}

func load(ctx context.Context, client *http.Client, base string, w workload, duration time.Duration, concurrency int) measurements {
	deadline := time.Now().Add(duration)
	var mu sync.Mutex
	var wg sync.WaitGroup
	m := measurements{Statuses: make(map[int]int64)}
	hist := make([]int64, 2048)
	start := time.Now()
	for range concurrency {
		wg.Go(func() {
			local := make([]int64, 2048)
			statuses := make(map[int]int64)
			var n, errs int64
			for time.Now().Before(deadline) && ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, w.Method, base+w.Path, bytes.NewReader(w.Body))
				req.Host = "appsec-benchmark.test"
				req.Header.Set("User-Agent", agent)
				if w.ContentType != "" {
					req.Header.Set("Content-Type", w.ContentType)
				}
				if w.Cookie != "" {
					req.Header.Set("Cookie", w.Cookie)
				}
				t := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errs++
				} else {
					_, readErr := io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					statuses[resp.StatusCode]++
					if readErr != nil || !expectedResponse(resp, w) {
						errs++
					}
				}
				local[latencyBucket(time.Since(t))]++
				n++
			}
			mu.Lock()
			defer mu.Unlock()
			m.Requests += n
			m.Errors += errs
			for i, v := range local {
				hist[i] += v
			}
			for k, v := range statuses {
				m.Statuses[k] += v
			}
		})
	}
	wg.Wait()
	m.Seconds = time.Since(start).Seconds()
	m.Throughput = float64(m.Requests) / m.Seconds
	m.P50 = percentile(hist, .50)
	m.P95 = percentile(hist, .95)
	m.P99 = percentile(hist, .99)
	return m
}

func balancedOrder(round, n int) []int {
	v := make([]int, n)
	for i := range v {
		v[i] = (round + i) % n
	}
	if round/n%2 == 1 {
		slices.Reverse(v)
	}
	return v
}

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrueParser/trueops-appsec/modules/appsec"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestNativeVirtualHostPolicies(t *testing.T) {
	f := nativeSetup(t)
	cookies := http.Header{}
	t.Run("selection-and-exceptions", func(t *testing.T) {
		for _, tc := range []struct {
			host, path string
			status     int
		}{
			{"site-a.test", "/waf/.env", 403}, {"site-b.test", "/waf/.env", 201},
			{"site-b.test", "/waf/.git/config", 403},
			{"site-b.test", "/waf/wp-content/uploads/payload.php", 403},
			{"site-b.test", "/waf/wp-content/uploads/payload.php/.env", 403},
			{"site-a.test", "/legacy/.env", 200}, // WAF exception still requires Bot challenge.
			{"site-c.test", "/legacy/.env", 403}, // SAME datasource, different host.
			{"site-a.test", "/other/.env", 403},
			{"site-a.test", "/legacy/.env/extra.env", 403},
			{"SITE-A.TEST:8080", "/legacy/.env", 200},
			{"site-a.test", "/wp-content/uploads/test.php/.env", 403},
			{"site-a.test", "/off/.env", 201}, {"site-a.test", "/absent/.env", 201},
			{"site-a.test", "/bot/.env", 200}, {"site-a.test", "/.env", 403},
			{"site-a.test", "/bot-exempt/.env", 403},
		} {
			f.check(t, tc.host, tc.path, tc.status, nil)
		}
	})
	t.Run("forged-selectors", func(t *testing.T) {
		h := http.Header{"X-Crowdsec-Appsec-Host": {"site-b.test"}, "X-Crowdsec-Appsec-Uri": {"/safe"}, "X-Crowdsec-Appsec-Ip": {"192.0.2.1"}, "X-Crowdsec-Appsec-Api-Key": {"wrong"}, "X-Crowdsec-Appsec-Verb": {"GET"}, "X-Crowdsec-Appsec-Profile": {"off"}, "X-Appsec-Policy": {"off"}, "X-Forwarded-Host": {"site-b.test"}, "Forwarded": {"host=site-b.test;for=192.0.2.1"}}
		f.check(t, "site-a.test", "/.env", 403, h)
		f.check(t, "site-c.test", "/legacy/.env", 403, h)
	})
	t.Run("native-cookies-and-challenge", func(t *testing.T) {
		r := f.check(t, "site-a.test", "/", 200, nil)
		if !strings.Contains(r.Header.Get("Content-Type"), "text/html") {
			t.Fatal("native challenge content type missing")
		}
		r = f.check(t, "site-a.test", "/__policy_test/grant", 307, nil)
		for _, cookie := range r.Cookies() {
			if cookie.Name == "__crowdsec_challenge" {
				cookies.Add("Cookie", cookie.Name+"="+cookie.Value)
			}
		}
		if cookies.Get("Cookie") == "" {
			t.Fatal("engine did not mint its native Bot exemption cookie")
		}
		f.check(t, "site-a.test", "/", 201, cookies)
		f.check(t, "site-a.test", "/.env", 403, cookies)
		f.check(t, "site-a.test", "/legacy/.env", 201, cookies)
		f.check(t, "site-a.test", "/legacy/.env?query=retained", 201, cookies)
		f.check(t, "site-a.test", "/Legacy/.env", 403, cookies)
		f.check(t, "site-a.test", "/other/.env?path=/legacy/.env", 403, cookies)
		f.check(t, "site-a.test", "/other/.env", 403, cookies)
		f.check(t, "site-c.test", "/legacy/.env", 403, cookies)
		f.check(t, "site-a.test", "/wp-content/uploads/test.php/.env", 403, cookies)
		f.check(t, "site-b.test", "/", 200, cookies) // Separate challenge secrets.
		challengeExchange(t, f)
		f.check(t, "site-a.test", "/crowdsec-internal/challenge/not-an-asset", 404, cookies)
	})
	if t.Failed() {
		return
	}
	t.Run("concurrent-isolation", func(t *testing.T) {
		var wg sync.WaitGroup
		failures := make(chan string, 128)
		cases := []struct {
			host, path string
			want       int
		}{
			{"site-a.test", "/waf/.env", 403}, {"site-b.test", "/waf/.env", 201},
			{"site-a.test", "/legacy/.env", 201}, {"site-c.test", "/legacy/.env", 403},
			{"site-a.test", "/wp-content/uploads/test.php/.env", 403}, {"site-b.test", "/waf/.git/config", 403},
		}
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 12; j++ {
					tc := cases[j%len(cases)]
					r, _, err := f.request(tc.host, tc.path, "", cookies)
					if err != nil {
						failures <- err.Error()
						return
					}
					if r.StatusCode != tc.want {
						failures <- fmt.Sprintf("%s %s: %d != %d", tc.host, tc.path, r.StatusCode, tc.want)
						return
					}
				}
			}()
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
	})
	t.Run("combined-single-capture-and-inspection", func(t *testing.T) { singleCapture(t, f, cookies) })
	t.Run("reload-and-restart", func(t *testing.T) {
		var reloads []float64
		for i := 0; i < 3; i++ {
			reloads = append(reloads, float64(f.reload(t, true).Microseconds())/1000)
		}
		f.report["caddy_reload_ms"] = reloads
		f.check(t, "site-a.test", "/legacy/.env", 201, cookies)
		f.check(t, "site-a.test", "/.env", 403, cookies)
		f.check(t, "site-a.test", "/", 200, nil)
		challengeExchange(t, f)
		f.server.stop()
		start := time.Now()
		f.server = startOwned(f.owner, f.root, "caddy-restart", f.caddy, "run", "--config", filepath.Join(f.root, "caddy.json"))
		waitOwned(t, f.server, f.address, f.admin)
		f.report["caddy_restart_ms"] = float64(time.Since(start).Microseconds()) / 1000
		f.check(t, "site-a.test", "/legacy/.env", 201, cookies)
		f.check(t, "site-a.test", "/.env", 403, cookies)
		f.engine.stop()
		start = time.Now()
		f.engine = startOwned(f.owner, f.root, "engine-restart", filepath.Join(f.bundle, "engine/crowdsec"), "-c", filepath.Join(f.root, "config.yaml"))
		addresses := []string{f.metrics}
		for _, addr := range f.ports {
			addresses = append(addresses, addr)
		}
		waitOwned(t, f.engine, addresses...)
		f.report["engine_restart_ms"] = float64(time.Since(start).Microseconds()) / 1000
		f.check(t, "site-a.test", "/legacy/.env", 201, cookies)
		f.check(t, "site-a.test", "/.env", 403, cookies)
		f.check(t, "site-b.test", "/waf/.env", 201, nil)
		f.check(t, "site-a.test", "/", 200, nil)
		challengeExchange(t, f)
	})
	t.Run("measurements", func(t *testing.T) { measurePolicies(t, f, cookies) })
	t.Run("failure-and-excluded-paths", func(t *testing.T) {
		f.engine.stop()
		f.check(t, "site-a.test", "/", 503, cookies)
		f.check(t, "site-a.test", "/crowdsec-internal/challenge/submit", 503, cookies)
		f.check(t, "site-a.test", "/off/.env", 201, nil)
		f.check(t, "site-a.test", "/absent/.env", 201, nil)
	})
}

func challengeExchange(t *testing.T, f *nativeFixture) {
	t.Helper()
	for _, path := range []string{"/crowdsec-internal/challenge/pow-worker.js", "/crowdsec-internal/challenge/fpscanner.js"} {
		r, body, err := f.request("site-a.test", path, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Type"), "javascript") || len(body) == 0 || r.Header.Get("X-Policy-Origin") != "" {
			t.Fatalf("native challenge asset failed: %s status=%d bytes=%d", path, r.StatusCode, len(body))
		}
	}
	r, body, err := f.request("site-a.test", "/crowdsec-internal/challenge/submit", `{}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != 200 || string(body) != `{"status":"failed"}` || len(r.Cookies()) != 0 || r.Header.Get("X-Policy-Origin") != "" {
		t.Fatal("invalid native challenge submission changed behavior or reached the origin")
	}
}

type countedBody struct {
	io.Reader
	bytes int
	reads int
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytes += n
	b.reads++
	return n, err
}
func (*countedBody) Close() error { return nil }

func singleCapture(t *testing.T, f *nativeFixture, cookies http.Header) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	h := &appsec.Handler{WAF: true, Bot: true, Endpoint: "http://" + f.ports["a-combined"] + "/", APIKey: f.key, Timeout: caddy.Duration(5 * time.Second), MaxBodyBytes: 10485760, MaxResponseBytes: 1048576, MaxInFlight: 4}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.Cleanup()
	payload := `{"message":"` + strings.Repeat("complete body ", 8192) + `"}`
	body := &countedBody{Reader: strings.NewReader(payload)}
	r := httptest.NewRequest("POST", "http://site-a.test/api/body?query=kept", nil)
	r.Body = body
	r.ContentLength = int64(len(payload))
	r.Header = cookies.Clone()
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "trueops-policy-acceptance")
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: "127.0.0.1"}))
	before := f.metricCount(t)
	if before == 0 {
		t.Fatal("native inspection metric unavailable; inspect metrics.txt")
	}
	called := false
	err := h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		called = true
		reads := body.reads
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		if string(b) != payload || body.bytes != len(payload) || body.reads != reads || r.Method != "POST" || r.Host != "site-a.test" || r.URL.RequestURI() != "/api/body?query=kept" {
			return fmt.Errorf("single capture/replay or original metadata violated")
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("valid native Bot cookie request did not continue")
	}
	if after := f.metricCount(t); after-before != 1 {
		t.Fatalf("combined inspection count delta=%v; want exactly 1", after-before)
	}
	t.Logf("combined body captured once: bytes=%d; native inspections=1; direct handler body/metadata intact", body.bytes)
	// Both-off does not even read an available body or contact the engine.
	off := &appsec.Handler{}
	unread := &countedBody{Reader: strings.NewReader(payload)}
	r.Body = unread
	if err := off.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })); err != nil {
		t.Fatal(err)
	}
	if unread.reads != 0 || f.metricCount(t) != before+1 {
		t.Fatal("off path performed security work")
	}
}

func measurePolicies(t *testing.T, f *nativeFixture, cookies http.Header) {
	t.Helper()
	cases := []struct{ name, host, path string }{
		{"absent", "site-a.test", "/absent/benign"},
		{"off", "site-a.test", "/off/benign"},
		{"site-a-waf", "site-a.test", "/waf/benign"},
		{"site-b-waf", "site-b.test", "/waf/benign"},
		{"site-a-combined", "site-a.test", "/benign"},
		{"site-a-exception", "site-a.test", "/legacy/.env"},
	}
	timings := map[string][]float64{}
	latencies := map[string][]float64{}
	for _, tc := range cases {
		for i := 0; i < 20; i++ {
			f.check(t, tc.host, tc.path, 201, cookies)
		}
	}
	aggregateRSS := func() int64 { return rss(t, f.engine.cmd.Process.Pid) + rss(t, f.server.cmd.Process.Pid) }
	initialRSS := aggregateRSS()
	sampledPeak := initialRSS
	ticksText, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := strconv.ParseFloat(strings.TrimSpace(string(ticksText)), 64)
	if err != nil || ticks <= 0 {
		t.Fatal("invalid native CLK_TCK")
	}
	engineCPU, caddyCPU := cpuTicks(t, f.engine.cmd.Process.Pid), cpuTicks(t, f.server.cmd.Process.Pid)
	for round := 0; round < 5; round++ {
		for offset := 0; offset < len(cases); offset++ {
			tc := cases[(round+offset)%len(cases)]
			start := time.Now()
			for i := 0; i < 100; i++ {
				requestStart := time.Now()
				f.check(t, tc.host, tc.path, 201, cookies)
				latencies[tc.name] = append(latencies[tc.name], float64(time.Since(requestStart).Nanoseconds())/1000)
			}
			timings[tc.name] = append(timings[tc.name], float64(time.Since(start).Nanoseconds())/100000)
			if current := aggregateRSS(); current > sampledPeak {
				sampledPeak = current
			}
		}
	}
	f.report["microseconds_per_request_rounds"] = timings
	f.report["request_measurement_cpu_seconds"] = object{"engine": float64(cpuTicks(t, f.engine.cmd.Process.Pid)-engineCPU) / ticks, "caddy": float64(cpuTicks(t, f.server.cmd.Process.Pid)-caddyCPU) / ticks}
	tails := object{}
	for name, values := range latencies {
		sort.Float64s(values)
		tails[name] = object{"p50": values[len(values)*50/100], "p95": values[len(values)*95/100], "p99": values[len(values)*99/100], "requests": len(values), "errors": 0}
	}
	f.report["latency_microseconds"] = tails
	engineRSS, caddyRSS := rss(t, f.engine.cmd.Process.Pid), rss(t, f.server.cmd.Process.Pid)
	f.report["resident_bytes"] = object{"engine_six_datasources": engineRSS, "caddy_three_hosts": caddyRSS, "runner": rss(t, os.Getpid()), "engine_plus_caddy": engineRSS + caddyRSS, "before_measured_requests": initialRSS, "sampled_peak": sampledPeak}
	var validation []float64
	for i := 0; i < 3; i++ {
		start := time.Now()
		cmd := exec.Command(f.caddy, "validate", "--config", filepath.Join(f.root, "caddy.json"))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		validation = append(validation, float64(time.Since(start).Microseconds())/1000)
	}
	f.report["caddy_config_validation_ms"] = validation
	for path, values := range timings {
		v := append([]float64(nil), values...)
		sort.Float64s(v)
		t.Logf("native loopback %s: median %.1f us/request (%d balanced rounds)", path, v[len(v)/2], len(v))
	}
	t.Logf("aggregate resident memory engine+Caddy=%d bytes; six datasources, three hosts; measurements include real engine policy cost", engineRSS+caddyRSS)
	if b, err := json.Marshal(f.report); err == nil {
		t.Logf("measurement evidence: %s", b)
	}
}

func cpuTicks(t *testing.T, pid int) int64 {
	t.Helper()
	b := string(readFile(t, fmt.Sprintf("/proc/%d/stat", pid)))
	fields := strings.Fields(b[strings.LastIndex(b, ")")+1:])
	if len(fields) < 13 {
		t.Fatal("invalid native process CPU counters")
	}
	u, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	s, err := strconv.ParseInt(fields[12], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return u + s
}

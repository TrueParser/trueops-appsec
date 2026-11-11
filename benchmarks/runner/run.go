package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type candidate struct {
	Name, Policy string
	Security     object
	External     bool
	Binary       string
}

func serveOwned(h http.Handler) (string, func(), error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	s := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	go s.Serve(l)
	stop := func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.Shutdown(c)
		s.Close()
	}
	return l.Addr().String(), stop, nil
}

func run(ctx context.Context, o options) error {
	if err := verifyBundle(o.Bundle); err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "trueops-appsec-benchmark-")
	if err != nil {
		return err
	}
	// Keep results, owned configs and logs for review; never remove unrelated files.
	fmt.Println("results_directory=" + root)
	if err = os.MkdirAll(filepath.Join(root, "public", "static"), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, "public", "static", "fixture.txt"), []byte("benchmark-static-file\n"), 0600); err != nil {
		return err
	}
	origin, stopOrigin, err := serveOwned(http.HandlerFunc(originHandler))
	if err != nil {
		return err
	}
	defer stopOrigin()
	key := "synthetic-fixture-key"
	endpoints := map[string]string{}
	var engine *child
	if o.Mode == "synthetic" {
		addr, stop, err := serveOwned(http.HandlerFunc(syntheticHandler))
		if err != nil {
			return err
		}
		defer stop()
		for _, p := range []string{"waf", "bot", "combined"} {
			endpoints[p] = "http://" + addr + "/"
		}
	} else {
		engine, endpoints, key, err = startEngine(ctx, o.Bundle, root)
		if err != nil {
			return err
		}
		defer engine.stop()
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	stock := filepath.Join(o.Bundle, "bin", "stock-caddy"+ext)
	bundle := filepath.Join(o.Bundle, "bin", "caddy"+ext)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cs := []candidate{{Name: "stock", Binary: stock}, {Name: "bundle-absent", Binary: bundle}, {Name: "bundle-disabled", Binary: bundle, Security: object{"handler": "trueops_appsec"}}}
	for _, p := range []string{"waf", "bot", "combined"} {
		h := handlerConfig(endpoints[p], key, p)
		cs = append(cs, candidate{Name: "external-" + p, Policy: p, Security: h, External: true, Binary: stock}, candidate{Name: "inprocess-" + p, Policy: p, Security: h, Binary: bundle})
	}
	works, err := benchmarkWorkloads()
	if err != nil {
		return err
	}
	if o.Quick {
		o.Repeats = 3
		o.Duration = 200 * time.Millisecond
		o.Warmup = 100 * time.Millisecond
		works = works[:2]
	}
	metadata := object{"mode": o.Mode, "quick_smoke_only": o.Quick, "go_version": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "load_generator": "same VPS as candidates and engine; shared-host closed-loop limitation", "protocol": "HTTP/1.1 cleartext loopback; HTTP/2/TLS/upgrade acceptance pending", "latency": "milliseconds; fixed logarithmic histogram, <=1% bucket resolution", "options": object{"duration": o.Duration.String(), "warmup": o.Warmup.String(), "repeats": o.Repeats, "concurrency": o.Concurrency}, "external_topology": "client -> bridge (same AppSec Handler) -> stock Caddy original content handler", "inprocess_topology": "client -> bundled Caddy AppSec -> original content handler", "real_browser_acceptance": "pending; HTTP probes do not execute browser JavaScript", "go_heap_allocations": "not inferred from RSS; use separate native microbenchmarks/profiles"}
	for _, p := range []string{"/proc/cpuinfo", "/proc/meminfo", "/etc/os-release", "/proc/version"} {
		if b, e := os.ReadFile(p); e == nil {
			metadata[filepath.Base(p)] = string(b)
		}
	}
	if b, e := os.ReadFile(filepath.Join(o.Bundle, "manifest.json")); e == nil {
		var m any
		if json.Unmarshal(b, &m) == nil {
			metadata["bundle_manifest"] = m
		}
	}
	if err = writeJSON(filepath.Join(root, "environment.json"), metadata); err != nil {
		return err
	}
	out, err := os.OpenFile(filepath.Join(root, "results.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	ticks := clockTicks()
	var incomplete bool
	for round := range o.Repeats {
		for _, index := range balancedOrder(round, len(cs)) {
			if err := ctx.Err(); err != nil {
				return err
			}
			c := cs[index]
			if err := runCandidate(ctx, o, root, self, origin, c, works, round, engine, ticks, enc); err != nil {
				incomplete = true
				fmt.Fprintln(os.Stderr, c.Name, ":", err)
				enc.Encode(object{"type": "candidate_failure", "candidate": c.Name, "round": round, "error": err.Error(), "mode": o.Mode})
			}
		}
	}
	if engine != nil {
		// Query only the private database using its explicit configuration.
		cmd := []string{"-c", filepath.Join(root, "engine", "config.yaml"), "decisions", "list", "-o", "json"}
		if err = privateCommand(ctx, filepath.Join(o.Bundle, "engine", "cscli"), root, filepath.Join(root, "private-decisions.json"), cmd...); err != nil {
			incomplete = true
		}
		b, e := os.ReadFile(filepath.Join(root, "private-decisions.json"))
		var decisions []json.RawMessage
		if e != nil || json.Unmarshal(b, &decisions) != nil || len(decisions) != 0 {
			incomplete = true
			fmt.Fprintln(os.Stderr, "private LAPI decision isolation needs review; see private-decisions.json")
		}
	}
	fmt.Println("raw_results=" + out.Name())
	if err = out.Sync(); err != nil {
		return err
	}
	if err = summarize(out.Name(), filepath.Join(root, "summary.json")); err != nil {
		return err
	}
	fmt.Println("Real browser, native arm64, HTTP/2/TLS, sustained pressure and release acceptance remain pending.")
	if incomplete {
		return errors.New("one or more candidates/preflights failed; preserve results and inspect owned logs")
	}
	return nil
}

func runCandidate(ctx context.Context, o options, root, self, origin string, c candidate, works []workload, round int, engine *child, ticks float64, enc *json.Encoder) error {
	dir := filepath.Join(root, strconv.Itoa(round)+"-"+c.Name)
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for _, diag := range []string{"version", "build-info", "list-modules"} {
		args := []string{diag}
		if diag == "list-modules" {
			args = append(args, "--packages")
		}
		if err := privateCommand(ctx, c.Binary, dir, filepath.Join(dir, diag+".txt"), args...); err != nil {
			return err
		}
	}
	addr, err := freeAddress()
	if err != nil {
		return err
	}
	security := c.Security
	if c.External {
		security = nil
	}
	config := filepath.Join(dir, "caddy.json")
	if err = writeJSON(config, caddyConfig(addr, origin, root, security)); err != nil {
		return err
	}
	server, err := startChild(dir, "caddy", c.Binary, "run", "--config", config)
	if err != nil {
		return err
	}
	defer server.stop()
	if err = waitPort(ctx, server, addr); err != nil {
		return err
	}
	children := map[string]*child{"caddy": server}
	if engine != nil {
		children["engine"] = engine
	}
	if c.External {
		bridgeAddr, err := freeAddress()
		if err != nil {
			return err
		}
		hc := filepath.Join(dir, "bridge.json")
		if err = writeJSON(hc, c.Security); err != nil {
			return err
		}
		b, err := startChild(dir, "bridge", self, "bridge", "--config", hc, "--listen", bridgeAddr, "--upstream", "http://"+addr)
		if err != nil {
			return err
		}
		defer b.stop()
		if err = waitPort(ctx, b, bridgeAddr); err != nil {
			return err
		}
		children["bridge"] = b
		addr = bridgeAddr
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxIdleConnsPerHost = o.Concurrency
	transport.MaxConnsPerHost = o.Concurrency
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	base := "http://" + addr
	if c.Policy != "" {
		if err = probeRemediation(client, base, o.Mode, c.Policy); err != nil {
			return err
		}
		if c.Policy != "waf" {
			if err = probeChallengeExchange(client, base, o.Mode); err != nil {
				return err
			}
		}
	}
	for _, w := range works {
		if o.Mode == "real" && (c.Policy == "bot" || c.Policy == "combined") && !strings.HasPrefix(w.Path, "/excluded/") {
			// The pinned scoring profile challenges every request without a valid
			// browser cookie. Measure that decision, never label it origin capacity.
			w.Challenge = true
			w.Name += "-first-challenge"
		}
		if err = check(client, base, w); err != nil {
			return err
		}
		if o.Warmup > 0 {
			load(ctx, client, base, w, o.Warmup, o.Concurrency)
		}
		before := captureUsage(children, ticks)
		m := load(ctx, client, base, w, o.Duration, o.Concurrency)
		after := captureUsage(children, ticks)
		for role, u := range after {
			u.CPUSeconds -= before[role].CPUSeconds
			after[role] = u
		}
		entry := object{"type": "measurement", "candidate": c.Name, "policy": c.Policy, "mode": o.Mode, "round": round, "workload": w.Name, "challenge_response": w.Challenge, "body_bytes": len(w.Body), "measurements": m, "process_usage": after, "rss_note": "end-of-window RSS; not peak RSS or retained Go heap"}
		if err = enc.Encode(entry); err != nil {
			return err
		}
		fmt.Printf("%s %s round=%d rps=%.1f p99_ms=%.3f errors=%d\n", c.Name, w.Name, round, m.Throughput, m.P99, m.Errors)
		if m.Errors != 0 || m.Requests == 0 {
			return errors.New("measurement contained errors; do not use as capacity evidence")
		}
	}
	return nil
}

func probeRemediation(client *http.Client, base, mode, policy string) error {
	if policy == "bot" && mode == "real" {
		return nil
	} // Browser verification is explicitly pending.
	// The pinned appsec-default profile loads appsec-generic-test out of band;
	// use its in-band vpatch-env-access rule to require a synchronous denial.
	path := "/.env"
	if mode == "synthetic" {
		path = "/appsec-test"
	}
	req, _ := http.NewRequest("GET", base+path, nil)
	req.Host = "appsec-benchmark.test"
	req.Header.Set("User-Agent", agent)
	r, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != 403 || r.Header.Get("X-Benchmark-Origin") != "" {
		return fmt.Errorf("native denial preflight failed: status=%d origin_reached=%t", r.StatusCode, r.Header.Get("X-Benchmark-Origin") != "")
	}
	if mode == "real" {
		for _, tc := range []struct{ method, path, body string }{
			{"GET", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", ""},
			{"POST", "/api/items", `{"wrong":true}`},
		} {
			if err := requireTerminalStatus(client, base, tc.method, tc.path, tc.body, 403); err != nil {
				return err
			}
		}
		// Quotas are deliberately exercised only inside this private datasource.
		// Later candidates share the same policy/counters; /login is never timed.
		for i := range 6 {
			req, _ := http.NewRequest("POST", base+"/login", strings.NewReader(`{}`))
			req.Host = "appsec-benchmark.test"
			req.Header.Set("User-Agent", agent)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if i == 5 && (resp.StatusCode != 429 || resp.Header.Get("X-Benchmark-Origin") != "") {
				return fmt.Errorf("native rate-limit preflight failed: %d", resp.StatusCode)
			}
		}
	}
	return nil
}

func requireTerminalStatus(client *http.Client, base, method, path, body string, status int) error {
	req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
	req.Host = "appsec-benchmark.test"
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != status || resp.Header.Get("X-Benchmark-Origin") != "" {
		return fmt.Errorf("native preflight %s: status=%d expected=%d", path, resp.StatusCode, status)
	}
	return nil
}

func probeChallengeExchange(client *http.Client, base, mode string) error {
	if mode == "synthetic" {
		req, _ := http.NewRequest("GET", base+"/challenge-probe", nil)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		if err != nil || resp.StatusCode != 200 || string(b) != "synthetic-challenge" || len(resp.Header.Values("Set-Cookie")) != 2 || resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Benchmark-Origin") != "" {
			return errors.New("synthetic challenge relay preflight failed")
		}
		return nil
	}
	for _, path := range []string{"pow-worker.js", "fpscanner.js"} {
		req, _ := http.NewRequest("GET", base+"/crowdsec-internal/challenge/"+path, nil)
		req.Header.Set("User-Agent", agent)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || len(b) == 0 || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") || resp.Header.Get("X-Benchmark-Origin") != "" {
			return fmt.Errorf("native asset relay failed: %s", path)
		}
	}
	req, _ := http.NewRequest("POST", base+"/crowdsec-internal/challenge/submit", strings.NewReader("not-a-valid-submission"))
	req.Header.Set("User-Agent", agent)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil || resp.StatusCode != 200 || !json.Valid(b) || len(resp.Cookies()) != 0 || resp.Header.Get("X-Benchmark-Origin") != "" {
		return errors.New("invalid challenge submission was not a terminal native failure")
	}
	return nil
}

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type object = map[string]any

type ownedProcess struct {
	cmd  *exec.Cmd
	done chan error
	log  *os.File
}

func startOwned(t *testing.T, root, name, binary string, args ...string) *ownedProcess {
	t.Helper()
	f, err := os.Create(filepath.Join(root, name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = root, f, f
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(root, "xdg-data"), "XDG_CONFIG_HOME="+filepath.Join(root, "xdg-config"))
	if err := cmd.Start(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	p := &ownedProcess{cmd: cmd, done: make(chan error, 1), log: f}
	go func() { p.done <- cmd.Wait(); close(p.done) }()
	t.Cleanup(p.stop)
	return p
}

func (p *ownedProcess) stop() {
	select {
	case <-p.done:
		p.log.Close()
		return
	default:
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	p.log.Close()
}

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func waitOwned(t *testing.T, p *ownedProcess, addresses ...string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for _, addr := range addresses {
		for {
			c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				c.Close()
				break
			}
			select {
			case err := <-p.done:
				t.Fatalf("owned process exited: %v; inspect %s", err, p.log.Name())
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("readiness timeout: %s; inspect %s", addr, p.log.Name())
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeYAML(t *testing.T, path string, v any) {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, b)
}

func shaFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type nativeFixture struct {
	owner                                                        *testing.T
	root, repo, bundle, caddy, api, metrics, address, admin, key string
	ports                                                        map[string]string
	engine, server                                               *ownedProcess
	config                                                       []byte
	report                                                       object
	client                                                       *http.Client
}

func nativeSetup(t *testing.T) *nativeFixture {
	t.Helper()
	if os.Getenv("TRUEOPS_APPSEC_TEST_LOCAL") != "1" || strings.EqualFold(os.Getenv("CI"), "true") {
		t.Skip("isolated native engine acceptance: requires TRUEOPS_APPSEC_TEST_LOCAL=1 outside CI")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("pinned engine artifact targets Linux/amd64; compile on Windows, execute on authorized native target")
	}
	f := &nativeFixture{owner: t, repo: os.Getenv("TRUEOPS_APPSEC_TEST_REPO"), bundle: os.Getenv("TRUEOPS_APPSEC_TEST_BUNDLE"), caddy: os.Getenv("TRUEOPS_APPSEC_TEST_CADDY"), ports: map[string]string{}, report: object{}, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if f.repo == "" || f.bundle == "" || f.caddy == "" {
		t.Fatal("set TRUEOPS_APPSEC_TEST_REPO, TRUEOPS_APPSEC_TEST_BUNDLE and TRUEOPS_APPSEC_TEST_CADDY to reviewed artifacts")
	}
	var err error
	f.root, err = os.MkdirTemp(os.Getenv("TRUEOPS_APPSEC_TEST_OUTPUT"), "trueops-policy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("private evidence directory: %s (contains generated secrets; do not publish it)", f.root)
	engine := filepath.Join(f.bundle, "engine", "crowdsec")
	cscli := filepath.Join(f.bundle, "engine", "cscli")
	for path, want := range map[string]string{engine: "1ae56d0d2272a1693211a6b746dc562fc4b8e981709db67a54cfc403c7a18788", cscli: "90218cfe2a445b2bf6ea93add789cd36555b7a8cd48a69b6f57c1259ddc18798"} {
		if shaFile(t, path) != want {
			t.Fatalf("pinned v1.8.2 artifact checksum mismatch: %s", path)
		}
	}
	f.report["engine_commit"] = "3d369d64eb3e9ba770ed39aedc83ffd3170aef4c"
	f.report["caddy_sha256"] = shaFile(t, f.caddy)
	f.report["engine_sha256"] = shaFile(t, engine)
	f.report["platform"] = runtime.GOOS + "/" + runtime.GOARCH
	f.report["load_generator"] = "same host; loopback HTTP/1.1; acceptance timings, not production capacity"
	f.report["diagnostics"] = "Caddy DEBUG and CrowdSec INFO enabled; timings include diagnostics"
	for _, dir := range []string{"appsec-configs", "appsec-rules", "data", "hub", "notifications", "plugins", "parsers", "scenarios", "postoverflows", "contexts", "collections", "patterns"} {
		if err := os.MkdirAll(filepath.Join(f.root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	var pins struct {
		Assets []struct{ Kind, Name, Path, SHA256 string } `json:"hub_assets"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(f.repo, "modules/appsec/profiles/pins.json")), &pins); err != nil {
		t.Fatal(err)
	}
	for _, asset := range pins.Assets {
		src := filepath.Join(f.bundle, "engine-template", asset.Kind, filepath.Base(asset.Path))
		if shaFile(t, src) != asset.SHA256 {
			t.Fatalf("pinned Hub checksum mismatch: %s", asset.Name)
		}
		writeFile(t, filepath.Join(f.root, asset.Kind, filepath.Base(asset.Path)), readFile(t, src))
	}
	for _, name := range []string{"site-a.yaml", "site-b.yaml", "exceptions.yaml"} {
		writeFile(t, filepath.Join(f.root, "appsec-configs", name), readFile(t, filepath.Join(f.repo, "modules/appsec/profiles/virtual-hosts", name)))
	}
	writeFile(t, filepath.Join(f.root, "hub/.index.json"), []byte("{}\n"))
	writeFile(t, filepath.Join(f.root, "simulation.yaml"), []byte("simulation: false\n"))
	writeFile(t, filepath.Join(f.root, "profiles.yaml"), readFile(t, filepath.Join(f.repo, "modules/appsec/profiles/no-firewall-decisions.yaml")))
	// Private acceptance-only cookie minting uses native post-evaluation behavior.
	// It is never installed by the operator examples or selected by a public header.
	for _, site := range []string{"a", "b"} {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		writeYAML(t, filepath.Join(f.root, "appsec-configs", "challenge-"+site+".yaml"), object{"name": "operator/site-" + site + "-challenge", "challenge": object{"master_secret": hex.EncodeToString(secret)}})
	}
	writeFile(t, filepath.Join(f.root, "appsec-configs", "test-bot.yaml"), []byte(`name: acceptance/bot-hooks
inband:
  pre_eval:
    - filter: req.URL.Path == "/bot-exempt/.env"
      apply: ['ExemptFromChallenge("isolated acceptance")']
  post_eval:
    - filter: req.URL.Path == "/__policy_test/grant"
      apply: ['GrantChallengeCookie("isolated acceptance")']
`))
	var acquisitions []string
	for _, site := range []string{"a", "b"} {
		for _, mode := range []string{"waf", "combined", "bot"} {
			id := site + "-" + mode
			f.ports[id] = freeAddress(t)
			configs := []string{}
			if mode != "bot" {
				configs = append(configs, "trueops/site-"+site+"-waf", "trueops/site-rule-exceptions")
			}
			if mode != "waf" {
				configs = append(configs, "acceptance/bot-hooks", "crowdsecurity/appsec-bot-challenge-scoring", "crowdsecurity/appsec-bot-challenge-scoring-balanced", "operator/site-"+site+"-challenge")
			}
			b, err := yaml.Marshal(object{"source": "appsec", "name": id, "listen_addr": f.ports[id], "path": "/", "body_read_timeout": "0s", "appsec_configs": configs, "labels": object{"type": "appsec", "site": site}})
			if err != nil {
				t.Fatal(err)
			}
			acquisitions = append(acquisitions, string(b))
		}
	}
	writeFile(t, filepath.Join(f.root, "acquis.yaml"), []byte(strings.Join(acquisitions, "---\n")))
	f.api, f.metrics, f.address, f.admin = freeAddress(t), freeAddress(t), freeAddress(t), freeAddress(t)
	_, metricsPort, _ := net.SplitHostPort(f.metrics)
	mp, _ := strconv.Atoi(metricsPort)
	path := func(s string) string { return filepath.Join(f.root, s) }
	writeYAML(t, path("config.yaml"), object{
		"common":           object{"daemonize": false, "log_media": "stdout", "log_level": "info"},
		"config_paths":     object{"config_dir": f.root, "data_dir": path("data"), "simulation_path": path("simulation.yaml"), "hub_dir": path("hub"), "index_path": path("hub/.index.json"), "notification_dir": path("notifications"), "plugin_dir": path("plugins")},
		"crowdsec_service": object{"acquisition_path": path("acquis.yaml"), "parser_routines": 1}, "cscli": object{"output": "human", "color": "never"},
		"db_config":  object{"type": "sqlite", "db_path": path("crowdsec.db")},
		"api":        object{"client": object{"credentials_path": path("credentials.yaml")}, "server": object{"listen_uri": f.api, "profiles_path": path("profiles.yaml"), "console_path": path("console.yaml"), "disable_usage_metrics_export": true, "trusted_ips": []string{"127.0.0.1"}}},
		"prometheus": object{"enabled": true, "listen_addr": "127.0.0.1", "listen_port": mp, "level": "full"},
	})
	writeFile(t, path("credentials.yaml"), []byte("url: http://"+f.api+"/\n"))
	run := func(name string, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, cscli, append([]string{"-c", path("config.yaml")}, args...)...)
		cmd.Dir = f.root
		b, err := cmd.Output()
		if err != nil {
			t.Fatalf("private %s: %v", name, err)
		}
		return b
	}
	run("machine setup", "machines", "add", "policy-acceptance", "--auto", "--file", path("credentials.yaml"))
	f.key = strings.TrimSpace(string(run("bouncer setup", "-o", "raw", "bouncers", "add", "policy-acceptance")))
	if f.key == "" {
		t.Fatal("empty private bouncer credential")
	}
	start := time.Now()
	f.engine = startOwned(t, f.root, "engine", engine, "-c", path("config.yaml"))
	addresses := []string{f.metrics}
	for _, addr := range f.ports {
		addresses = append(addresses, addr)
	}
	waitOwned(t, f.engine, addresses...)
	f.report["engine_startup_ms"] = float64(time.Since(start).Microseconds()) / 1000
	f.report["datasources"] = len(f.ports)
	f.config = f.caddyConfig(t)
	writeFile(t, path("caddy.json"), f.config)
	start = time.Now()
	f.server = startOwned(t, f.root, "caddy", f.caddy, "run", "--config", path("caddy.json"))
	waitOwned(t, f.server, f.address, f.admin)
	f.report["caddy_startup_ms"] = float64(time.Since(start).Microseconds()) / 1000
	t.Cleanup(func() {
		f.client.CloseIdleConnections()
		b, _ := json.MarshalIndent(f.report, "", "  ")
		writeFile(t, path("results.json"), b)
	})
	return f
}

func (f *nativeFixture) caddyConfig(t *testing.T) []byte {
	t.Helper()
	var routes []object
	for _, site := range []string{"a", "b", "c"} {
		policy := site
		if site == "c" {
			policy = "a"
		} // Shared datasource proves host-scoped exceptions.
		var modes []object
		for _, mode := range []string{"combined", "off", "waf", "bot", "absent"} {
			match := object{}
			if mode != "combined" {
				match["path"] = []string{"/" + mode + "/*"}
			}
			chain := []object{}
			if mode != "absent" {
				h := object{"handler": "trueops_appsec"}
				if mode != "off" {
					h["waf"] = mode != "bot"
					h["bot"] = mode != "waf"
					h["endpoint"] = "http://" + f.ports[policy+"-"+mode] + "/"
					h["api_key"] = f.key
					h["timeout"] = "5s"
					h["max_body_bytes"] = 10485760
					h["max_response_bytes"] = 1048576
					h["max_in_flight"] = 64
				}
				chain = append(chain, h)
			}
			chain = append(chain, object{"handler": "static_response", "status_code": 201, "body": "original-handler", "headers": object{"X-Policy-Origin": []string{"yes"}}})
			modes = append(modes, object{"match": []object{match}, "handle": chain, "terminal": true})
		}
		// Exact path modes before the combined catch-all, preserving challenge routes.
		modes = append(modes[1:], modes[0])
		routes = append(routes, object{"match": []object{{"host": []string{"site-" + site + ".test"}}}, "handle": []object{{"handler": "subroute", "routes": modes}}, "terminal": true})
	}
	b, err := json.Marshal(object{"admin": object{"listen": f.admin, "config": object{"persist": false}}, "storage": object{"module": "file_system", "root": filepath.Join(f.root, "storage")}, "logging": object{"logs": object{"default": object{"level": "DEBUG"}}}, "apps": object{"http": object{"grace_period": "2s", "servers": object{"policy": object{"listen": []string{f.address}, "read_timeout": "10s", "idle_timeout": "10s", "automatic_https": object{"disable": true}, "routes": routes}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *nativeFixture) request(host, path, body string, headers http.Header) (*http.Response, []byte, error) {
	method := "GET"
	if body != "" {
		method = "POST"
	}
	r, err := http.NewRequest(method, "http://"+f.address+path, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	r.Host = host
	r.Header = headers.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set("User-Agent", "trueops-policy-acceptance")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.client.Do(r)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

func (f *nativeFixture) check(t *testing.T, host, path string, want int, headers http.Header) *http.Response {
	t.Helper()
	r, b, err := f.request(host, path, "", headers)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != want {
		t.Fatalf("host=%s path=%s: status=%d want=%d body_bytes=%d origin=%q", host, path, r.StatusCode, want, len(b), r.Header.Get("X-Policy-Origin"))
	}
	if (want == 201) != (r.Header.Get("X-Policy-Origin") == "yes") {
		t.Fatalf("incorrect direct continuation for host=%s path=%s", host, path)
	}
	return r
}

func (f *nativeFixture) metricCount(t *testing.T) float64 {
	t.Helper()
	r, err := f.client.Get("http://" + f.metrics + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.root, "metrics.txt"), b)
	var sum float64
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(line, "cs_appsec_inband_parsing_time_seconds_count{") {
			fields := strings.Fields(line)
			v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
			if err != nil {
				t.Fatal(err)
			}
			sum += v
		}
	}
	return sum
}

func (f *nativeFixture) reload(t *testing.T, force bool) time.Duration {
	t.Helper()
	r, err := http.NewRequest("POST", "http://"+f.admin+"/load", bytes.NewReader(f.config))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if force {
		r.Header.Set("Cache-Control", "must-revalidate")
	}
	start := time.Now()
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("Caddy reload status: %d", resp.StatusCode)
	}
	return time.Since(start)
}

func rss(t *testing.T, pid int) int64 {
	t.Helper()
	b := readFile(t, fmt.Sprintf("/proc/%d/status", pid))
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			v, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return v * 1024
		}
	}
	t.Fatal("RSS unavailable")
	return 0
}

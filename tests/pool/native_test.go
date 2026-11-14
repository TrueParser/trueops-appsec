package pool_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrueParser/trueops-appsec/modules/upstreampool"
)

type echo struct {
	Version string `json:"version"`
	Node    int    `json:"node"`
	Method  string `json:"method"`
	URI     string `json:"uri"`
	Host    string `json:"host"`
	Digest  string `json:"digest"`
}

type fixture struct {
	admin, site string
	client      *http.Client
	control     *http.Client
	v1, v2      []string
	held        <-chan struct{}
	release     func()
	waitHeld    func()
	retire      func(bool) error
	reload      func()
	restart     func()

	latencyMu sync.Mutex
	latencies []time.Duration
}

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func certificate(t *testing.T, root string) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pool-acceptance"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for name, data := range map[string][]byte{"cert.pem": certPEM,
		"key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("fixture root certificate rejected")
	}
	return roots
}

func setup(t *testing.T) *fixture {
	t.Helper()
	binary := os.Getenv("TRUEOPS_POOL_CADDY")
	if binary == "" {
		t.Skip("set TRUEOPS_POOL_CADDY to the exact unpublished candidate; uses only disposable owned fixtures")
	}
	if os.Getenv("TRUEOPS_POOL_V1_TARGETS") != "" &&
		(os.Getenv("TRUEOPS_APPSEC_TEST_LOCAL") != "1" || os.Getenv("CI") == "true") {
		t.Skip("external disposable fixtures require TRUEOPS_APPSEC_TEST_LOCAL=1 outside CI")
	}
	root := t.TempDir()
	held, unblock := make(chan struct{}), make(chan struct{})
	var heldOnce, releaseOnce sync.Once
	var closedOld atomic.Bool
	f := &fixture{held: held, release: func() { releaseOnce.Do(func() { close(unblock) }) },
		retire: func(retire bool) error { closedOld.Store(retire); return nil }}
	f.waitHeld = func() {
		select {
		case <-f.held:
		case <-time.After(5 * time.Second):
			t.Fatal("held V1 request did not reach origin")
		}
	}
	// Cleanup releases held work before shutting down origins even after failure.
	t.Cleanup(f.release)
	var origins []*httptest.Server
	localNodes := 3
	if os.Getenv("TRUEOPS_POOL_V1_TARGETS") != "" {
		localNodes = 0
	}
	for _, version := range []string{"v1", "v2"} {
		for node := range localNodes {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if version == "v1" && closedOld.Load() {
					http.Error(w, "retired origin reached", http.StatusGone)
					return
				}
				if r.URL.Path == "/hold" && version == "v1" {
					heldOnce.Do(func() { close(held) })
					select {
					case <-unblock:
					case <-r.Context().Done():
						return
					}
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "body incomplete", http.StatusBadRequest)
					return
				}
				digest := sha256.Sum256(body)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(echo{Version: version, Node: node, Method: r.Method,
					URI: r.RequestURI, Host: r.Host, Digest: hex.EncodeToString(digest[:])})
			}))
			origins = append(origins, server)
			addr := strings.TrimPrefix(server.URL, "http://")
			if version == "v1" {
				f.v1 = append(f.v1, addr)
			} else {
				f.v2 = append(f.v2, addr)
			}
		}
	}
	t.Cleanup(func() {
		f.release()
		for _, origin := range origins {
			origin.Close()
		}
	})
	if v1 := os.Getenv("TRUEOPS_POOL_V1_TARGETS"); v1 != "" {
		f.externalOrigins(t, v1, os.Getenv("TRUEOPS_POOL_V2_TARGETS"))
	}
	roots := certificate(t, root)
	f.admin, f.site = "http://"+freeAddress(t), "https://"+freeAddress(t)
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	f.client = &http.Client{Transport: transport, Timeout: 15 * time.Second}
	f.control = &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	t.Cleanup(f.control.CloseIdleConnections)
	type object = map[string]any
	proxy := object{"handler": "reverse_proxy", "dynamic_upstreams": object{"source": "trueops_pool", "pool": "site"},
		"load_balancing": object{"selection_policy": object{"policy": "round_robin"}}}
	staticTargets := make([]object, len(f.v1))
	for i, addr := range f.v1 {
		staticTargets[i] = object{"dial": addr}
	}
	baseline := object{"handler": "reverse_proxy", "upstreams": staticTargets,
		"load_balancing": object{"selection_policy": object{"policy": "round_robin"}}}
	config := object{
		"admin":   object{"listen": strings.TrimPrefix(f.admin, "http://"), "config": object{"persist": false}},
		"storage": object{"module": "file_system", "root": filepath.Join(root, "storage")},
		"logging": object{"logs": object{"default": object{"level": "INFO"},
			"pools": object{"level": "DEBUG", "include": []string{"trueops_pools"}}}},
		"apps": object{
			"trueops_pools": object{"state_id": "native-" + root, "pools": object{"site": upstreampool.Spec{Revision: 1, Targets: f.v1},
				"other": upstreampool.Spec{Revision: 1, Targets: f.v1}}},
			"tls": object{"certificates": object{"load_files": []object{{"certificate": filepath.Join(root, "cert.pem"), "key": filepath.Join(root, "key.pem")}}}},
			"http": object{"grace_period": "2s", "servers": object{"pool_acceptance": object{
				"listen": []string{strings.TrimPrefix(f.site, "https://")}, "automatic_https": object{"disable": true},
				"tls_connection_policies": []object{{}},
				"routes": []object{
					{"match": []object{{"path": []string{"/unrelated"}}}, "handle": []object{{"handler": "static_response", "body": "unrelated"}}, "terminal": true},
					{"match": []object{{"path": []string{"/baseline"}}}, "handle": []object{baseline}, "terminal": true},
					{"handle": []object{{"handler": "trueops_pool", "pool": "site"}, proxy}},
				},
			}}},
		},
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "caddy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "caddy.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	start := func() (*exec.Cmd, chan error) {
		cmd := exec.Command(binary, "run", "--config", path)
		cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(root, "data"), "XDG_CONFIG_HOME="+filepath.Join(root, "config"))
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		return cmd, done
	}
	cmd, done := start()
	t.Cleanup(func() {
		f.release()
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = log.Close()
		if b, err := os.ReadFile(logPath); err == nil {
			if len(b) > 18000 {
				b = b[len(b)-18000:]
			}
			t.Logf("candidate log (bounded):\n%s", b)
		}
	})
	waitReady := func() {
		deadline := time.Now().Add(15 * time.Second)
		for {
			resp, err := f.control.Get(f.admin + "/upstream-pools/site")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == 200 {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("candidate Admin API did not become ready")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitReady()
	f.restart = func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		<-done
		cmd, done = start()
		waitReady()
	}
	f.reload = func() {
		req, err := http.NewRequest("POST", f.admin+"/load", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cache-Control", "must-revalidate")
		resp, err := f.control.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			t.Fatalf("reload status=%d: %s", resp.StatusCode, b)
		}
		waitReady()
	}
	t.Logf("candidate=%s pid=%d site=%s admin=%s TLS_verified=true config_loads=1", binary, cmd.Process.Pid, f.site, f.admin)
	return f
}

func (f *fixture) status(t *testing.T, id string) upstreampool.Status {
	t.Helper()
	resp, err := f.control.Get(f.admin + "/upstream-pools/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var s upstreampool.Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil || resp.StatusCode != 200 {
		t.Fatalf("pool read status=%d decode=%v", resp.StatusCode, err)
	}
	return s
}

func (f *fixture) put(t *testing.T, u upstreampool.Update, want int) {
	t.Helper()
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("PUT", f.admin+"/upstream-pools/site", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.control.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("pool update status=%d want=%d", resp.StatusCode, want)
	}
}

func request(client *http.Client, base, path, method string, body []byte) (echo, int, error) {
	r, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		return echo{}, 0, err
	}
	r.Header.Set("X-Upstream-Pool", "other")
	resp, err := client.Do(r)
	if err != nil {
		return echo{}, 0, err
	}
	defer resp.Body.Close()
	var e echo
	err = json.NewDecoder(resp.Body).Decode(&e)
	if resp.StatusCode != 200 {
		return e, resp.ProtoMajor, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return e, resp.ProtoMajor, err
}

func TestCandidatePoolCutovers(t *testing.T) {
	f := setup(t)
	initial := f.status(t, "site")
	configBefore, err := f.control.Get(f.admin + "/config/")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := io.ReadAll(configBefore.Body)
	_ = configBefore.Body.Close()
	heldDone := make(chan error, 1)
	go func() {
		e, _, err := request(f.client, f.site, "/hold", "POST", []byte("held-body"))
		if err == nil && e.Version != "v1" {
			err = fmt.Errorf("held request changed version: %s", e.Version)
		}
		heldDone <- err
	}()
	f.waitHeld()
	u := upstreampool.Update{ExpectedInstance: initial.Instance, ExpectedRevision: 1,
		Spec: upstreampool.Spec{Revision: 2, Targets: f.v2}}
	f.put(t, u, 200)
	f.put(t, u, 200)
	u.Targets = f.v1
	f.put(t, u, 409)
	for _, body := range []string{`{"unknown":true}`, `{} {}`, `{"revision":2,"targets":[]}`} {
		req, err := http.NewRequest("PUT", f.admin+"/upstream-pools/site", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := f.control.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("malformed control message accepted: %d", resp.StatusCode)
		}
	}
	status := f.status(t, "site")
	if len(status.Draining) != 1 || status.Draining[0].Revision != 1 || status.Draining[0].Active != 1 {
		t.Fatalf("held request drain lost: %+v", status)
	}
	for i := range 30 {
		body := bytes.Repeat([]byte{0, 255, byte(i)}, 1000)
		e, protocol, err := request(f.client, f.site, "/echo?q=preserved", "POST", body)
		digest := sha256.Sum256(body)
		if err != nil || protocol != 2 || e.Version != "v2" || e.Method != "POST" ||
			e.URI != "/echo?q=preserved" || e.Digest != hex.EncodeToString(digest[:]) || e.Host != strings.TrimPrefix(f.site, "https://") {
			t.Fatalf("HTTP/2/body continuation failed: echo=%+v protocol=%d err=%v", e, protocol, err)
		}
	}
	f.release()
	if err := <-heldDone; err != nil {
		t.Fatal(err)
	}
	if status := f.status(t, "site"); len(status.Draining) != 0 {
		t.Fatalf("completed old generation retained: %+v", status)
	}
	if err := f.retire(true); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if e, _, err := request(f.client, f.site, "/echo", "GET", nil); err != nil || e.Version != "v2" {
			t.Fatalf("retired old pool selected: %+v %v", e, err)
		}
	}
	if err := f.retire(false); err != nil {
		t.Fatal(err)
	}
	t.Log("held V1 POST completed after V2 cutover; binary bodies, HTTP/2, duplicate/stale updates and old-target retirement passed")
	var requests, failures atomic.Int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); wg.Wait() }()
	for worker := range 6 {
		wg.Go(func() {
			tlsConfig := f.client.Transport.(*http.Transport).TLSClientConfig.Clone()
			// The earlier HTTP/2 transport populated ALPN on its config. Do not
			// advertise h2 on the HTTP/1-only control clients that clone it.
			tlsConfig.NextProtos = nil
			transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig,
				ForceAttemptHTTP2: worker%3 == 2, DisableKeepAlives: worker%3 == 0}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for ctx.Err() == nil {
				start := time.Now()
				e, _, err := request(client, f.site, "/echo", "GET", nil)
				f.latencyMu.Lock()
				f.latencies = append(f.latencies, time.Since(start))
				f.latencyMu.Unlock()
				requests.Add(1)
				if err != nil || (e.Version != "v1" && e.Version != "v2") {
					if failures.Add(1) <= 5 {
						t.Logf("traffic error: %+v %v", e, err)
					}
				}
			}
		})
	}
	start := time.Now()
	for revision := uint64(3); revision <= 102; revision++ {
		targets, version := f.v1, "v1"
		if revision%2 == 0 {
			targets, version = f.v2, "v2"
		}
		f.put(t, upstreampool.Update{ExpectedInstance: initial.Instance, ExpectedRevision: revision - 1,
			Spec: upstreampool.Spec{Revision: revision, Targets: targets}}, 200)
		for range 3 {
			e, _, err := request(f.client, f.site, "/echo?revision="+strconv.FormatUint(revision, 10), "GET", nil)
			if err != nil || e.Version != version {
				cancel()
				wg.Wait()
				t.Fatalf("new request after acknowledged cutover selected wrong version: %+v %v", e, err)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	elapsed := time.Since(start)
	if failures.Load() != 0 || requests.Load() == 0 {
		t.Fatalf("requests=%d failures=%d", requests.Load(), failures.Load())
	}
	slices.Sort(f.latencies)
	t.Logf("pool_changes=100 workers=6 mixed_fresh_H1_persistent_H1_H2 requests=%d failures=%d seconds=%.3f rps=%.1f p50=%s p99=%s",
		requests.Load(), failures.Load(), elapsed.Seconds(), float64(requests.Load())/elapsed.Seconds(),
		f.latencies[len(f.latencies)/2], f.latencies[len(f.latencies)*99/100])
	if other := f.status(t, "other"); other.Revision != 1 || !slices.Equal(other.Targets, f.v1) {
		t.Fatal("unrelated pool mutated")
	}
	resp, err := f.client.Get(f.site + "/unrelated")
	if err != nil {
		t.Fatal(err)
	}
	unrelated, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(unrelated) != "unrelated" {
		t.Fatal("unrelated native route changed")
	}
	configAfter, err := f.control.Get(f.admin + "/config/")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := io.ReadAll(configAfter.Body)
	_ = configAfter.Body.Close()
	if !bytes.Equal(before, after) || f.status(t, "site").Instance != initial.Instance {
		t.Fatal("pool updates replaced native configuration")
	}
	t.Log("native config unchanged, same pool instance, unrelated pool/route unchanged; no /load or /config write issued")
}

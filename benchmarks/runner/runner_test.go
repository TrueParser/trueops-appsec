package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func TestBundleIntegrityRejectsChangedBinary(t *testing.T) {
	dir := t.TempDir()
	body := []byte("reviewed fixture")
	if err := os.WriteFile(filepath.Join(dir, "candidate"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(digest(body)+"  candidate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBundle(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "candidate"), []byte("different bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBundle(dir); err == nil {
		t.Fatal("unverified replacement binary accepted")
	}
	t.Log("candidate integrity checked before subprocess execution")
}

func TestSummaryRetainsCandidateFailures(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "results.jsonl")
	output := filepath.Join(dir, "summary.json")
	data := `{"type":"measurement","candidate":"stock","workload":"get","mode":"synthetic","measurements":{"requests_per_second":100,"p99_ms":2}}` + "\n" + `{"type":"candidate_failure","candidate":"external-waf"}` + "\n"
	if err := os.WriteFile(input, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := summarize(input, output); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		CandidateFailures int `json:"candidate_failures"`
	}
	if err = json.Unmarshal(b, &report); err != nil || report.CandidateFailures != 1 {
		t.Fatal("failure disappeared from summary")
	}
}

func TestCRSExtractionStaysPrivateAndRetainsData(t *testing.T) {
	for _, escape := range []bool{false, true} {
		dir := t.TempDir()
		archive := filepath.Join(dir, "rules.zip")
		f, err := os.Create(archive)
		if err != nil {
			t.Fatal(err)
		}
		z := zip.NewWriter(f)
		entries := map[string]string{"coreruleset-4.30.0/crs-setup.conf.example": "fixture setup", "coreruleset-4.30.0/rules/fixture.data": "fixture data"}
		if escape {
			entries["../escape"] = "invalid"
		}
		for name, body := range entries {
			w, err := z.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = w.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		dataDir := filepath.Join(dir, "private-data")
		err = extractCRS(archive, dataDir)
		if escape {
			if err == nil {
				t.Fatal("zip escaped private directory")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dataDir, "fixture.data"))
		if err != nil || string(b) != "fixture data" {
			t.Fatal("native Coraza data file not retained")
		}
	}
}

func TestGeneratedConfigurationUsesNativeCaddySchema(t *testing.T) {
	data, err := json.Marshal(caddyConfig("127.0.0.1:45678", "127.0.0.1:45679", t.TempDir(), nil))
	if err != nil {
		t.Fatal(err)
	}
	var cfg caddy.Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if err = caddy.Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	t.Log("generated benchmark configuration passes native Caddy validation")
}

func TestPreflightRejectsChallengeHTTP200(t *testing.T) {
	challenge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("challenge, not application"))
	}))
	defer challenge.Close()
	if err := check(challenge.Client(), challenge.URL, workload{Name: "get", Method: "GET", Path: "/"}); err == nil {
		t.Fatal("challenge accepted as successful origin response")
	}
	m := load(context.Background(), challenge.Client(), challenge.URL, workload{Method: "GET", Path: "/"}, 30*time.Millisecond, 2)
	t.Logf("challenge response requests=%d errors=%d", m.Requests, m.Errors)
	if m.Requests == 0 || m.Errors != m.Requests {
		t.Fatal("challenge throughput counted as success")
	}
}

func TestBodyAndMetadataPreflight(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(originHandler))
	defer s.Close()
	w := workload{Name: "upload", Method: "POST", Path: "/upload?q=1&q=2", Body: bytes.Repeat([]byte("a"), 256<<10)}
	if err := check(s.Client(), s.URL, w); err != nil {
		t.Fatal(err)
	}
	t.Log("entire upload, Host, method and query preserved")
}

func TestHistogramAndBalancedPositions(t *testing.T) {
	h := make([]int64, 2048)
	h[latencyBucket(time.Millisecond)] = 100
	if p := percentile(h, .99); p < 1 || p > 1.02 {
		t.Fatalf("percentile ms=%v", p)
	}
	const n = 9
	seen := make([]map[int]bool, n)
	for i := range seen {
		seen[i] = make(map[int]bool)
	}
	for round := range n {
		for position, candidate := range balancedOrder(round, n) {
			seen[candidate][position] = true
		}
	}
	for i, s := range seen {
		if len(s) != n {
			t.Fatalf("candidate %d positions=%v", i, s)
		}
	}
}

func TestProcStatAndPrivateEngineConfiguration(t *testing.T) {
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[11] = "150"
	fields[12] = "50"
	fields[21] = "10"
	u := parseUsage("123 (name with ) parentheses) "+strings.Join(fields, " "), 100, 4096)
	if !u.Available || u.CPUSeconds != 2 || u.RSSBytes != 40960 {
		t.Fatalf("usage=%+v", u)
	}
	if parseUsage("malformed", 100, 4096).Available {
		t.Fatal("invalid proc data presented as measured")
	}
	dir := t.TempDir()
	cfg := engineConfig(dir, "127.0.0.1:45678")
	if strings.Contains(cfg, "/etc/crowdsec") || strings.Contains(cfg, "/var/lib") || strings.Contains(cfg, "online_client:") || !strings.Contains(cfg, "disable_usage_metrics_export: true") {
		t.Fatal("engine escaped private/offline boundaries")
	}
	t.Log("private engine configuration keeps CAPI and metrics disabled")
}

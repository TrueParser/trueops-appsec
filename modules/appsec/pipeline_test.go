package appsec

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
)

func TestNativeCaddyRoutesAndOriginalReverseProxy(t *testing.T) {
	var inspections, origins atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origins.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.URL.RawQuery != "q=1&q=2" || r.Method != "PATCH" || r.Host != "site-a.test" || string(body) != "entire upload" {
			t.Error("native origin request changed")
		}
		_, _ = io.WriteString(w, "original-handler")
	}))
	defer origin.Close()
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inspections.Add(1)
		if r.Header.Get("X-Crowdsec-Appsec-Ip") != "127.0.0.1" {
			t.Error("untrusted forwarding header replaced Caddy identity")
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Error(err)
		}
		switch strings.Split(r.Header.Get("X-Crowdsec-Appsec-Uri"), "?")[0] {
		case "/blocked":
			reply(w, 403, `{"action":"ban","http_status":403}`)
		case challengePrefix + "fpscanner.js":
			reply(w, 403, `{"action":"challenge","user_body_content":"native-fixture-asset","user_headers":{"Content-Type":["application/javascript"]}}`)
		default:
			reply(w, 200, `{"action":"allow"}`)
		}
	}))
	defer engine.Close()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err = reservation.Close(); err != nil {
		t.Fatal(err)
	}
	originURL, _ := url.Parse(origin.URL)
	proxy := map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": originURL.Host}}}
	protected := map[string]any{"handler": "trueops_appsec", "waf": true, "bot": true, "endpoint": engine.URL, "api_key": "fixture-key", "timeout": "2s", "max_body_bytes": 65536, "max_response_bytes": 131072, "max_in_flight": 4}
	config := map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"storage": map[string]any{"module": "file_system", "root": t.TempDir()},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "DEBUG"}}},
		"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"fixture": map[string]any{
			"listen": []string{address}, "read_timeout": "2s", "automatic_https": map[string]any{"disable": true},
			"routes": []any{
				map[string]any{"match": []any{map[string]any{"host": []string{"site-a.test"}}}, "handle": []any{protected, proxy}, "terminal": true},
				map[string]any{"handle": []any{map[string]any{"handler": "trueops_appsec"}, map[string]any{"handler": "static_response", "body": "unprotected"}}},
			},
		}}}},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = caddy.Load(raw, true); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	}()
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		host, path string
		status     int
		body       string
	}{
		{"site-a.test", "/allowed?q=1&q=2", 200, "original-handler"},
		{"site-a.test", "/blocked", 403, "Forbidden\n"},
		{"site-a.test", challengePrefix + "fpscanner.js", 200, "native-fixture-asset"},
		{"site-a.test", challengePrefix + "unknown", 404, "Not Found\n"},
		{"site-b.test", "/anything", 200, "unprotected"},
	} {
		req, err := http.NewRequest("PATCH", "http://"+address+tc.path, strings.NewReader("entire upload"))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = tc.host
		req.Header.Set("X-Forwarded-For", "203.0.113.99")
		req.Header.Set("X-Crowdsec-Appsec-Ip", "203.0.113.99")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != tc.status || string(body) != tc.body {
			t.Fatalf("%s%s: status=%d body=%q", tc.host, tc.path, resp.StatusCode, body)
		}
	}
	if inspections.Load() != 4 || origins.Load() != 1 {
		t.Fatalf("native path bypass/leak: inspections=%d origins=%d", inspections.Load(), origins.Load())
	}
}

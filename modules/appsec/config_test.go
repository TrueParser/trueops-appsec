package appsec

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

const configFixture = `trueops_appsec {
 waf on
 bot on
 endpoint http://127.0.0.1:7422/
 api_key fixture-engine-key
 timeout 2s
 max_body_bytes 65536
 max_response_bytes 131072
 max_in_flight 4
}`

func TestCaddyfileAndModuleRegistration(t *testing.T) {
	var h Handler
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(configFixture)); err != nil {
		t.Fatal(err)
	}
	if !h.WAF || !h.Bot || h.MaxInFlight != 4 || h.MaxBodyBytes != 65536 {
		t.Fatal("Caddyfile fields lost")
	}
	if _, err := caddy.GetModule("http.handlers.trueops_appsec"); err != nil {
		t.Fatal(err)
	}
	config := `:8080 {
 route {
` + configFixture + `
 respond "original"
 }
}`
	adapter := caddyconfig.GetAdapter("caddyfile")
	data, warnings, err := adapter.Adapt(caddyfile.Format([]byte(config)), nil)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("adapt err=%v warnings=%v", err, warnings)
	}
	if !strings.Contains(string(data), `"handler":"trueops_appsec"`) {
		t.Fatal("native handler missing")
	}
	// Validation provisions modules without opening an AppSec connection.
	var nativeConfig caddy.Config
	if err := json.Unmarshal(data, &nativeConfig); err != nil {
		t.Fatal(err)
	}
	if err := caddy.Validate(&nativeConfig); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidConfigurationIsRejectedWithoutSecrets(t *testing.T) {
	for _, edit := range []struct {
		name   string
		mutate func(*Handler)
	}{
		{"url", func(h *Handler) { h.Endpoint = "http://user:secret@engine/" }},
		{"scheme", func(h *Handler) { h.Endpoint = "ftp://engine/" }},
		{"key", func(h *Handler) { h.APIKey = "secret\r\ninjection" }},
		{"body", func(h *Handler) { h.MaxBodyBytes = 0 }},
		{"response", func(h *Handler) { h.MaxResponseBytes = -1 }},
		{"duration", func(h *Handler) { h.Timeout = 0 }},
		{"concurrency", func(h *Handler) { h.MaxInFlight = 0 }},
		{"ca", func(h *Handler) { h.CAFile = "secret" }},
	} {
		t.Run(edit.name, func(t *testing.T) {
			var h Handler
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(configFixture)); err != nil {
				t.Fatal(err)
			}
			edit.mutate(&h)
			err := h.Validate()
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid or secret-bearing error: %v", err)
			}
		})
	}
	for _, config := range []string{
		"trueops_appsec positional",
		"trueops_appsec {\n waf yes\n}",
		"trueops_appsec {\n unknown secret\n}",
		"trueops_appsec {\n bot off\n bot on\n}",
		"trueops_appsec {\n timeout secret\n}",
		"trueops_appsec {\n bot off extra\n}",
	} {
		var h Handler
		if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(config)); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid parser result: %v", err)
		}
	}
}

func TestTLSVerificationAndPrivateCA(t *testing.T) {
	engine := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reply(w, 200, `{"action":"allow"}`) }))
	defer engine.Close()
	h := configured(t, engine.URL, true, false)
	w, called := execute(t, h, incoming("GET", "http://site.test/", ""))
	if called || w.Code != 503 {
		t.Fatal("untrusted TLS allowed")
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: engine.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	h = configured(t, engine.URL, true, false, func(h *Handler) { h.CAFile = ca })
	_, called = execute(t, h, incoming("GET", "http://site.test/", ""))
	if !called {
		t.Fatal("configured private CA rejected")
	}
	if err := os.WriteFile(ca, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := h.Provision(ctx); err == nil {
		t.Fatal("invalid CA accepted")
	}
}

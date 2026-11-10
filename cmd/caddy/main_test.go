package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeCLI(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "disabled.json")
	if err = os.WriteFile(config, []byte(`{"admin":{"disabled":true},"apps":{"http":{"servers":{"fixture":{"listen":["127.0.0.1:0"],"automatic_https":{"disable":true},"routes":[{"handle":[{"handler":"trueops_appsec"},{"handler":"static_response","body":"ok"}]}]}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		args, want []string
	}{
		{"version", []string{"version"}, []string{"v2.11.9"}},
		{"build-info", []string{"build-info"}, []string{"go1.27.3", "github.com/caddyserver/caddy/v2"}},
		{"modules", []string{"list-modules"}, []string{"http.handlers.trueops_appsec", "http.handlers.reverse_proxy", "http.handlers.file_server"}},
		{"validate", []string{"validate", "--config", config}, []string{"Valid configuration"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestCLIHelperProcess$", "--"}, tc.args...)
			cmd := exec.CommandContext(ctx, self, args...)
			cmd.Env = append(os.Environ(), "TRUEOPS_APPSEC_CLI_HELPER=1")
			output, err := cmd.CombinedOutput()
			t.Logf("native CLI %s:\n%s", tc.name, output)
			if err != nil {
				t.Fatalf("CLI failed: %v", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(output), want) {
					t.Fatalf("CLI output missing %q", want)
				}
			}
		})
	}
}

func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("TRUEOPS_APPSEC_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"caddy"}, os.Args[i+1:]...)
			main()
			return
		}
	}
	t.Fatal("missing helper CLI arguments")
}

package integration

import (
	"encoding/json"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"gopkg.in/yaml.v3"
)

// This portable contract check needs neither an engine nor maintainer assets.
func TestVersionedNativePolicyContract(t *testing.T) {
	root := filepath.Join("..", "..", "modules", "appsec", "profiles")
	var catalog struct {
		Version   string
		HubCommit string `json:"hub_commit"`
		Groups    map[string]string
		Required  []string
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(root, "virtual-hosts", "catalog.json")), &catalog); err != nil {
		t.Fatal(err)
	}
	var pins struct {
		Hub    struct{ Commit string }
		Assets []struct{ Kind, Name, Version, SHA256 string } `json:"hub_assets"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(root, "pins.json")), &pins); err != nil {
		t.Fatal(err)
	}
	if catalog.HubCommit != pins.Hub.Commit || catalog.Version == "" {
		t.Fatal("catalog revision is not bound to pinned Hub")
	}
	rules := map[string]bool{}
	for _, asset := range pins.Assets {
		if asset.Kind == "appsec-rules" {
			if asset.Version == "" || len(asset.SHA256) != 64 {
				t.Fatal("unversioned catalog asset")
			}
			rules[asset.Name] = true
		}
	}
	for group, pattern := range catalog.Groups {
		count := 0
		for name := range rules {
			if ok, _ := path.Match(pattern, name); ok {
				count++
			}
		}
		if count == 0 {
			t.Fatalf("empty catalog group: %s", group)
		}
		t.Logf("pinned catalog group %s: %d rules", group, count)
	}
	for _, name := range catalog.Required {
		if !rules[name] {
			t.Fatalf("missing required processor configuration: %s", name)
		}
	}
	selected := map[string]map[string]bool{}
	for _, site := range []string{"a", "b"} {
		var profile struct {
			Name  string
			Rules []string `yaml:"inband_rules"`
		}
		if err := yaml.Unmarshal(readFile(t, filepath.Join(root, "virtual-hosts", "site-"+site+".yaml")), &profile); err != nil {
			t.Fatal(err)
		}
		selected[site] = map[string]bool{}
		for _, pattern := range profile.Rules {
			count := 0
			for name := range rules {
				if ok, _ := path.Match(pattern, name); ok {
					selected[site][name] = true
					count++
				}
			}
			if count == 0 {
				t.Fatalf("unresolved native rule selection: %s", pattern)
			}
		}
		if !selected[site]["crowdsecurity/base-config"] {
			t.Fatal("body processors omitted")
		}
	}
	if !selected["a"]["crowdsecurity/vpatch-env-access"] || selected["b"]["crowdsecurity/vpatch-env-access"] || !selected["b"]["crowdsecurity/vpatch-git-config"] || !selected["b"]["crowdsecurity/generic-wordpress-uploads-php"] {
		t.Fatal("examples do not express required independent selections")
	}
	var exceptions struct {
		Inband struct {
			PreEval []struct {
				Filter string
				Apply  []string
			} `yaml:"pre_eval"`
		}
	}
	if err := yaml.Unmarshal(readFile(t, filepath.Join(root, "virtual-hosts", "exceptions.yaml")), &exceptions); err != nil {
		t.Fatal(err)
	}
	if len(exceptions.Inband.PreEval) != 2 {
		t.Fatal("exception fixture missing")
	}
	for _, hook := range exceptions.Inband.PreEval {
		if !strings.Contains(hook.Filter, "req.Host") || !strings.Contains(hook.Filter, "req.URL.Path") {
			t.Fatal("exception must bind host and path")
		}
		for _, apply := range hook.Apply {
			if apply != `RemoveInBandRuleByName("crowdsecurity/vpatch-env-access")` {
				t.Fatal("exception changes more than the intended rule")
			}
		}
	}
}

func TestVirtualHostCaddyfileExample(t *testing.T) {
	t.Setenv("APPSEC_API_KEY", "portable-fixture-only")
	input := readFile(t, filepath.Join("..", "..", "modules", "appsec", "profiles", "virtual-hosts", "Caddyfile"))
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("native Caddyfile adapter unavailable")
	}
	_, warnings, err := adapter.Adapt(input, map[string]any{"filename": "Caddyfile"})
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range warnings {
		t.Logf("Caddyfile warning: %s", warning.Message)
	}
}

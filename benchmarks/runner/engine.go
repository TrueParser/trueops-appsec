package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular bundled input: %s", rel)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0600)
	})
}

func privateCommand(ctx context.Context, binary, dir, output string, args ...string) error {
	f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func startEngine(ctx context.Context, bundle, root string) (*child, map[string]string, string, error) {
	dir := filepath.Join(root, "engine")
	if err := copyTree(filepath.Join(bundle, "engine-template"), dir); err != nil {
		return nil, nil, "", err
	}
	if err := extractCRS(filepath.Join(bundle, "coreruleset-4.30.0-minimal.zip"), filepath.Join(dir, "data")); err != nil {
		return nil, nil, "", err
	}
	api, err := freeAddress()
	if err != nil {
		return nil, nil, "", err
	}
	ports := map[string]string{}
	for _, p := range []string{"waf", "bot", "combined"} {
		a, e := freeAddress()
		if e != nil {
			return nil, nil, "", e
		}
		ports[p] = a
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return nil, nil, "", err
	}
	// Runtime secrets are created only inside the private temporary VPS directory.
	challenge := "name: benchmark/site-a-challenge\nchallenge:\n  master_secret: " + hex.EncodeToString(secret) + "\n"
	if err = os.WriteFile(filepath.Join(dir, "appsec-configs", "benchmark-challenge.yaml"), []byte(challenge), 0600); err != nil {
		return nil, nil, "", err
	}
	config := engineConfig(dir, api)
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, []byte(config), 0600); err != nil {
		return nil, nil, "", err
	}
	// cscli needs a URL while creating the first private machine. It replaces
	// this private placeholder with a newly generated credential, never host data.
	creds := filepath.Join(dir, "local_api_credentials.yaml")
	if err = os.WriteFile(creds, []byte("url: http://"+api+"/\n"), 0600); err != nil {
		return nil, nil, "", err
	}
	var acquisition strings.Builder
	for _, p := range []string{"waf", "bot", "combined"} {
		fmt.Fprintf(&acquisition, "---\nsource: appsec\nname: benchmark-%s\nlisten_addr: %s\npath: /\nbody_read_timeout: 0\nappsec_configs:\n", p, ports[p])
		if p != "bot" {
			acquisition.WriteString("  - crowdsecurity/appsec-default\n  - trueops/native-waf\n  - trueops/native-features\n")
		}
		if p != "waf" {
			acquisition.WriteString("  - crowdsecurity/appsec-bot-challenge-scoring\n  - crowdsecurity/appsec-bot-challenge-scoring-balanced\n  - benchmark/site-a-challenge\n")
		}
		acquisition.WriteString("labels:\n  type: appsec\n  site: benchmark-site-a\n")
	}
	if err = os.WriteFile(filepath.Join(dir, "acquis.yaml"), []byte(acquisition.String()), 0600); err != nil {
		return nil, nil, "", err
	}
	cscli := filepath.Join(bundle, "engine", "cscli")
	if err = privateCommand(ctx, cscli, dir, filepath.Join(dir, "machine-setup.log"), "-c", path, "machines", "add", "benchmark", "--auto", "--file", creds); err != nil {
		return nil, nil, "", fmt.Errorf("private machine setup: %w", err)
	}
	keyFile := filepath.Join(dir, "appsec-key.txt")
	if err = privateCommand(ctx, cscli, dir, keyFile, "-c", path, "-o", "raw", "bouncers", "add", "benchmark"); err != nil {
		return nil, nil, "", fmt.Errorf("private bouncer setup: %w", err)
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, "", err
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return nil, nil, "", fmt.Errorf("empty private bouncer key")
	}
	c, err := startChild(dir, "crowdsec", filepath.Join(bundle, "engine", "crowdsec"), "-c", path)
	if err != nil {
		return nil, nil, "", err
	}
	for _, addr := range ports {
		if err = waitPort(ctx, c, addr); err != nil {
			c.stop()
			return nil, nil, "", err
		}
	}
	endpoints := map[string]string{}
	for mode, addr := range ports {
		endpoints[mode] = "http://" + addr + "/"
	}
	return c, endpoints, key, nil
}

func extractCRS(archive, dataDir string) error {
	z, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer z.Close()
	for _, file := range z.File {
		rel := filepath.FromSlash(file.Name)
		target := filepath.Join(dataDir, rel)
		if filepath.IsAbs(rel) || !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dataDir)+string(os.PathSeparator)) {
			return fmt.Errorf("CRS archive path escapes private directory")
		}
		if file.FileInfo().IsDir() {
			if err = os.MkdirAll(target, 0700); err != nil {
				return err
			}
			continue
		}
		if !file.Mode().IsRegular() {
			return fmt.Errorf("unsupported CRS archive entry")
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		in, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			in.Close()
			return err
		}
		_, err = io.Copy(out, in)
		in.Close()
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	setup := filepath.Join(dataDir, "coreruleset-4.30.0", "crs-setup.conf")
	b, err := os.ReadFile(setup + ".example")
	if err != nil {
		return err
	}
	if err = os.WriteFile(setup, b, 0600); err != nil {
		return err
	}
	paths, err := filepath.Glob(filepath.Join(dataDir, "coreruleset-4.30.0", "rules", "*.data"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dataDir, filepath.Base(path)), b, 0600); err != nil {
			return err
		}
	}
	return nil
}

func engineConfig(dir, addr string) string {
	// JSON string quoting is valid YAML and handles all private filesystem paths.
	q := func(name string) string { b, _ := json.Marshal(filepath.Join(dir, name)); return string(b) }
	return fmt.Sprintf(`common:
  daemonize: false
  log_media: stdout
  log_level: info
config_paths:
  config_dir: %s
  data_dir: %s
  simulation_path: %s
  hub_dir: %s
  index_path: %s
  notification_dir: %s
  plugin_dir: %s
crowdsec_service:
  acquisition_path: %s
  parser_routines: 1
cscli:
  output: human
  color: never
db_config:
  type: sqlite
  db_path: %s
api:
  client:
    credentials_path: %s
  server:
    listen_uri: %s
    profiles_path: %s
    console_path: %s
    disable_usage_metrics_export: true
    trusted_ips: [127.0.0.1]
prometheus:
  enabled: false
`, q(""), q("data"), q("simulation.yaml"), q("hub"), q("hub/.index.json"), q("notifications"), q("plugins"), q("acquis.yaml"), q("crowdsec.db"), q("local_api_credentials.yaml"), addr, q("profiles.yaml"), q("console.yaml"))
}

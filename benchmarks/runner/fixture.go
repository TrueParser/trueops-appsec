package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/TrueParser/trueops-appsec/modules/appsec"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const agent = "TrueOps-AppSec-Benchmark/1.0"

func benchmarkWorkloads() ([]workload, error) {
	var upload bytes.Buffer
	form := multipart.NewWriter(&upload)
	file, err := form.CreateFormFile("file", "fixture.bin")
	if err != nil {
		return nil, err
	}
	if _, err = file.Write(bytes.Repeat([]byte("0123456789abcdef"), 16<<10)); err != nil {
		return nil, err
	}
	if err = form.Close(); err != nil {
		return nil, err
	}
	return []workload{
		{Name: "get", Method: "GET", Path: "/get?q=1&q=2"},
		{Name: "post", Method: "POST", Path: "/post", ContentType: "application/json", Body: []byte(`{"name":"benchmark"}`)},
		{Name: "upload-256k", Method: "POST", Path: "/upload", ContentType: form.FormDataContentType(), Body: upload.Bytes()},
		{Name: "static", Method: "GET", Path: "/static/fixture.txt", Static: true},
		{Name: "excluded", Method: "POST", Path: "/excluded/body", ContentType: "application/json", Body: []byte(`{"name":"excluded"}`)},
	}, nil
}

func digest(data []byte) string { v := sha256.Sum256(data); return hex.EncodeToString(v[:]) }

func originHandler(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, (10<<20)+1))
	if err != nil || len(data) > 10<<20 {
		http.Error(w, "invalid benchmark body", 400)
		return
	}
	w.Header().Set("X-Benchmark-Origin", "owned")
	w.Header().Set("X-Benchmark-Method", r.Method)
	w.Header().Set("X-Benchmark-Target", r.URL.RequestURI())
	w.Header().Set("X-Benchmark-Host", r.Host)
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, digest(data))
}

// This fixture is deliberately synthetic; its results are never native acceptance.
func syntheticHandler(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read failure", 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	uri := r.Header.Get("X-Crowdsec-Appsec-Uri")
	if strings.Contains(uri, "/challenge-probe") {
		w.WriteHeader(403)
		io.WriteString(w, `{"action":"challenge","http_status":200,"user_body_content":"synthetic-challenge","user_headers":{"Content-Security-Policy":["default-src 'none'"]},"user_cookies":["a=b; Path=/","c=d; Path=/"]}`)
		return
	}
	if strings.Contains(uri, "appsec-test") || strings.Contains(string(data), "benchmark-deny") {
		w.WriteHeader(403)
		io.WriteString(w, `{"action":"ban"}`)
		return
	}
	io.WriteString(w, `{"action":"allow"}`)
}

func serveBridge(args []string) error {
	f := flag.NewFlagSet("bridge", flag.ContinueOnError)
	config := f.String("config", "", "private handler configuration")
	listen := f.String("listen", "", "loopback listener")
	upstream := f.String("upstream", "", "original stock Caddy content server")
	if err := f.Parse(args); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("bridge requires loopback")
	}
	data, err := os.ReadFile(*config)
	if err != nil {
		return err
	}
	var h appsec.Handler
	if err = json.Unmarshal(data, &h); err != nil {
		return err
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err = h.Provision(ctx); err != nil {
		return err
	}
	defer h.Cleanup()
	u, err := url.Parse(*upstream)
	if err != nil {
		return err
	}
	if u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		return errors.New("bridge upstream must be loopback HTTP")
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { proxy.ServeHTTP(w, r); return nil })
	server := &http.Server{Addr: *listen, ReadTimeout: 30 * time.Second, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(ip).IsLoopback() {
			http.Error(w, "benchmark is loopback only", 403)
			return
		}
		// The bridge is the ingress in this topology, so identity comes from its
		// socket, never a public forwarded header. The runner uses loopback clients.
		r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: ip}))
		if strings.HasPrefix(r.URL.Path, "/excluded/") {
			proxy.ServeHTTP(w, r)
			return
		}
		if err := h.ServeHTTP(w, r, next); err != nil {
			fmt.Fprintln(os.Stderr, "bridge response write failed")
		}
	})}
	return server.ListenAndServe()
}

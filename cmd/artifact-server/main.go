// Command artifact-server serves only the immutable public benchmark artifacts.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func artifactHandler(dir string) (http.Handler, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make(map[string]string)
	for _, e := range entries {
		name := e.Name()
		if e.Type().IsRegular() && (strings.HasSuffix(name, ".tar.gz") || name == "SHA256SUMS") {
			files["/"+name] = filepath.Join(dir, name)
		}
	}
	if len(files) == 0 {
		return nil, errors.New("no public artifacts")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(405)
			return
		}
		path, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, "artifact unavailable", 503)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			http.Error(w, "artifact unavailable", 503)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, info.Name(), info.ModTime(), f)
	}), nil
}

func main() {
	dir := flag.String("root", "", "directory containing public immutable archives and SHA256SUMS")
	addr := flag.String("listen", "127.0.0.1:0", "loopback download listener")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("listen must use a loopback IP")
	}
	h, err := artifactHandler(*dir)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Open(filepath.Join(*dir, "SHA256SUMS"))
	if err != nil {
		log.Fatal(err)
	}
	sum := sha256.New()
	_, err = io.Copy(sum, f)
	f.Close()
	if err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("download_listener=%s checksums_sha256=%s\n", l.Addr(), hex.EncodeToString(sum.Sum(nil)))
	s := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, WriteTimeout: 10 * time.Minute}
	log.Fatal(s.Serve(l))
}

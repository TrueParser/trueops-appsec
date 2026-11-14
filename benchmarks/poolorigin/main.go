// Command poolorigin serves disposable versioned origins on a private network.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type gate struct {
	mu      sync.Mutex
	release chan struct{}
	open    bool
	retired bool
	held    int
	served  int64
}

func (g *gate) handler(version string, node int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		switch r.URL.Path {
		case "/__pool_state":
			if r.Method != "GET" {
				g.mu.Unlock()
				w.WriteHeader(405)
				return
			}
			state := struct {
				Held    int    `json:"held"`
				Served  int64  `json:"served"`
				Node    int    `json:"node"`
				Version string `json:"version"`
				Retired bool   `json:"retired"`
			}{g.held, g.served, node, version, g.retired}
			g.mu.Unlock()
			_ = json.NewEncoder(w).Encode(state)
			return
		case "/__pool_reset", "/__pool_release", "/__pool_retire", "/__pool_restore":
			if r.Method != "POST" {
				g.mu.Unlock()
				w.WriteHeader(405)
				return
			}
			switch r.URL.Path {
			case "/__pool_reset":
				if g.held != 0 {
					g.mu.Unlock()
					w.WriteHeader(409)
					return
				}
				g.release, g.open, g.retired = make(chan struct{}), false, false
			case "/__pool_release":
				if !g.open {
					close(g.release)
					g.open = true
				}
			case "/__pool_retire":
				g.retired = true
			case "/__pool_restore":
				g.retired = false
			}
			g.mu.Unlock()
			w.WriteHeader(204)
			return
		}
		if g.retired {
			g.mu.Unlock()
			http.Error(w, "retired fixture reached", http.StatusGone)
			return
		}
		g.served++
		if r.URL.Path == "/hold" && version == "v1" {
			g.held++
			release := g.release
			g.mu.Unlock()
			select {
			case <-release:
			case <-r.Context().Done():
			}
			g.mu.Lock()
			g.held--
		}
		g.mu.Unlock()
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "fixture body limit/read failure", 400)
			return
		}
		digest := sha256.Sum256(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Version string `json:"version"`
			Node    int    `json:"node"`
			Method  string `json:"method"`
			URI     string `json:"uri"`
			Host    string `json:"host"`
			Digest  string `json:"digest"`
		}{version, node, r.Method, r.RequestURI, r.Host, hex.EncodeToString(digest[:])})
	})
}

func main() {
	bind := flag.String("bind", "127.0.0.1", "existing private-network or loopback IP")
	node := flag.Int("node", 1, "fixture node identity")
	v1port := flag.Int("v1-port", 52991, "V1 disposable origin port")
	v2port := flag.Int("v2-port", 52992, "V2 disposable origin port")
	duration := flag.Duration("duration", 30*time.Minute, "maximum fixture lifetime")
	flag.Parse()
	ip := net.ParseIP(*bind)
	if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) || *duration <= 0 {
		log.Fatal("bind must be a private/loopback IP and duration positive")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, *duration)
	defer timeout()
	servers := make([]*http.Server, 0, 2)
	listeners := make([]net.Listener, 0, 2)
	for i, port := range []int{*v1port, *v2port} {
		l, err := net.Listen("tcp", net.JoinHostPort(*bind, fmt.Sprint(port)))
		if err != nil {
			for _, prior := range listeners {
				_ = prior.Close()
			}
			log.Fatal(err)
		}
		g := &gate{release: make(chan struct{})}
		s := &http.Server{Handler: g.handler(fmt.Sprintf("v%d", i+1), *node), ReadHeaderTimeout: 5 * time.Second}
		listeners = append(listeners, l)
		servers = append(servers, s)
		log.Printf("fixture node=%d version=v%d listen=%s lifetime=%s", *node, i+1, l.Addr(), *duration)
	}
	for i, server := range servers {
		go func() {
			if err := server.Serve(listeners[i]); err != nil && err != http.ErrServerClosed {
				log.Print(err)
				cancel()
			}
		}()
	}
	<-ctx.Done()
	for _, server := range servers {
		_ = server.Close()
	}
}

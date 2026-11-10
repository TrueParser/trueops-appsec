package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type child struct {
	cmd  *exec.Cmd
	done chan error
	log  *os.File
}

func startChild(dir, name, binary string, args ...string) (*child, error) {
	f, err := os.OpenFile(filepath.Join(dir, name+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, f, f
	// Avoid Caddy or subprocesses reading/writing the operator's XDG state.
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(dir, "xdg-data"), "XDG_CONFIG_HOME="+filepath.Join(dir, "xdg-config"))
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan error, 1), log: f}
	go func() { c.done <- cmd.Wait(); close(c.done) }()
	return c, nil
}

func (c *child) stop() {
	if c == nil {
		return
	}
	select {
	case <-c.done:
		c.log.Close()
		return
	default:
	}
	// Signal only this exact owned child, never a process name or managed service.
	if err := c.cmd.Process.Signal(os.Interrupt); err != nil {
		_ = c.cmd.Process.Kill()
	}
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
	c.log.Close()
}

func freeAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().String()
	err = l.Close()
	return addr, err
}

func waitPort(ctx context.Context, c *child, addr string) error {
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case err := <-c.done:
			return fmt.Errorf("owned process exited: %v; inspect %s", err, c.log.Name())
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("owned process readiness timeout; inspect " + c.log.Name())
		case <-tick.C:
		}
	}
}

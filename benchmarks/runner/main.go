// Command appsec-bench runs isolated comparisons; it never manages host services.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

type options struct {
	Bundle               string
	Mode                 string
	Duration, Warmup     time.Duration
	Repeats, Concurrency int
	Quick                bool
}

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "benchmark:", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	if len(args) > 0 && args[0] == "bridge" {
		return serveBridge(args[1:])
	}
	f := flag.NewFlagSet("appsec-bench", flag.ContinueOnError)
	var o options
	f.StringVar(&o.Bundle, "bundle", ".", "verified extracted immutable bundle")
	f.StringVar(&o.Mode, "mode", "real", "real or synthetic (integration overhead only)")
	f.DurationVar(&o.Duration, "duration", 10*time.Second, "measurement duration per candidate/workload")
	f.DurationVar(&o.Warmup, "warmup", 2*time.Second, "warmup per candidate/workload")
	f.IntVar(&o.Repeats, "repeats", 9, "balanced rounds (at least 3; multiples of 9 balance all positions)")
	f.IntVar(&o.Concurrency, "concurrency", 16, "closed-loop local load workers")
	f.BoolVar(&o.Quick, "quick", false, "short smoke only; never performance acceptance")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || (o.Mode != "real" && o.Mode != "synthetic") || o.Duration <= 0 || o.Warmup < 0 || o.Repeats < 3 || o.Concurrency < 1 {
		return errors.New("invalid benchmark options")
	}
	if o.Mode == "real" && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64") {
		return errors.New("bundled real engine requires Linux amd64; run on the authorized VPS")
	}
	var err error
	o.Bundle, err = filepath.Abs(o.Bundle)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return run(ctx, o)
}

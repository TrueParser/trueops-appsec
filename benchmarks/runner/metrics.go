package main

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type processUsage struct {
	CPUSeconds float64 `json:"cpu_seconds"`
	RSSBytes   int64   `json:"rss_bytes"`
	Available  bool    `json:"available"`
}

func clockTicks() float64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	b, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	return v
}

func usage(pid int, ticks float64) processUsage {
	if ticks <= 0 {
		return processUsage{}
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return processUsage{}
	}
	return parseUsage(string(b), ticks, int64(os.Getpagesize()))
}

func parseUsage(stat string, ticks float64, pageSize int64) processUsage {
	end := strings.LastIndex(stat, ")")
	if end < 0 || ticks <= 0 {
		return processUsage{}
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 22 {
		return processUsage{}
	}
	u, e1 := strconv.ParseFloat(fields[11], 64)
	s, e2 := strconv.ParseFloat(fields[12], 64)
	rss, e3 := strconv.ParseInt(fields[21], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil {
		return processUsage{}
	}
	return processUsage{CPUSeconds: (u + s) / ticks, RSSBytes: rss * pageSize, Available: true}
}

func captureUsage(children map[string]*child, ticks float64) map[string]processUsage {
	u := make(map[string]processUsage)
	u["runner_and_origin"] = usage(os.Getpid(), ticks)
	for name, c := range children {
		u[name] = usage(c.cmd.Process.Pid, ticks)
	}
	return u
}

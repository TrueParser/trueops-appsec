package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

func summarize(path, output string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	type row struct {
		Type, Candidate, Workload, Mode string
		Measurements                    measurements
	}
	groups := map[string][]measurements{}
	var failures int
	d := json.NewDecoder(f)
	for {
		var r row
		err = d.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if r.Type != "measurement" {
			failures++
			continue
		}
		groups[r.Candidate+"|"+r.Workload+"|"+r.Mode] = append(groups[r.Candidate+"|"+r.Workload+"|"+r.Mode], r.Measurements)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	rows := []object{}
	for _, key := range keys {
		parts := strings.Split(key, "|")
		samples := groups[key]
		rates := []float64{}
		tails := []float64{}
		var errors int64
		for _, m := range samples {
			rates = append(rates, m.Throughput)
			tails = append(tails, m.P99)
			errors += m.Errors
		}
		slices.Sort(rates)
		slices.Sort(tails)
		median := func(v []float64) float64 {
			n := len(v)
			if n%2 == 0 {
				return (v[n/2-1] + v[n/2]) / 2
			}
			return v[n/2]
		}
		rows = append(rows, object{"candidate": parts[0], "workload": parts[1], "mode": parts[2], "runs": len(samples), "errors": errors, "median_requests_per_second": median(rates), "median_p99_ms": median(tails)})
		fmt.Printf("median %s %s runs=%d rps=%.1f p99_ms=%.3f errors=%d\n", parts[0], parts[1], len(samples), median(rates), median(tails), errors)
	}
	return writeJSON(output, object{"candidate_failures": failures, "comparisons": rows, "acceptance": "pending native/browser/performance review; compare identical workload and decision labels only"})
}

// Command probe runs a small random NS/TXT sample against live resolvers for
// sanity checking and performance assessment during development.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"psl-monitor/internal/dnscheck"
	"psl-monitor/internal/psl"
)

func main() {
	file := flag.String("psl", "/tmp/opencode/psl.dat", "PSL file")
	n := flag.Int("n", 200, "sample size")
	workers := flag.Int("w", 64, "workers")
	qps := flag.Float64("qps", 25, "per-resolver qps")
	section := flag.String("section", "", "icann|private|'' (both)")
	txt := flag.Bool("txt", false, "also query _psl TXT on private rules")
	verbose := flag.Bool("v", false, "print every result")
	flag.Parse()
	b, err := os.ReadFile(*file)
	if err != nil {
		panic(err)
	}
	l, err := psl.Parse(b)
	if err != nil {
		panic(err)
	}
	var tg []psl.Target
	for _, t := range l.Targets() {
		if *section == "" || t.Section == *section {
			tg = append(tg, t)
		}
	}
	rand.Shuffle(len(tg), func(i, j int) { tg[i], tg[j] = tg[j], tg[i] })
	if *n < len(tg) {
		tg = tg[:*n]
	}
	pool, err := dnscheck.NewPool(dnscheck.Options{QPS: *qps, Timeout: 2500 * time.Millisecond})
	if err != nil {
		panic(err)
	}
	var mu sync.Mutex
	counts := map[string]int{}
	incons := 0
	var slow []string
	start := time.Now()
	dnscheck.Runner(context.Background(), *workers, tg, func(ctx context.Context, t psl.Target) {
		ts := time.Now()
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		lk := pool.QueryNS(c, t.Name, nil)
		el := time.Since(ts)
		line := fmt.Sprintf("%-8s %-40s %-9s %5dms %s | %s", t.Section, t.Name, lk.Status, el.Milliseconds(), strings.Join(lk.Records, ","), lk.Summary())
		if *txt && t.Section == psl.SectionPrivate {
			for _, ri := range t.Rules {
				r := l.Rules[ri]
				tl := pool.QueryTXT(c, "_psl."+r.Name)
				line += fmt.Sprintf("\n    _psl.%s %s %v", r.Name, tl.Status, tl.Records)
			}
		}
		mu.Lock()
		counts[lk.Status]++
		if lk.Inconsistent {
			incons++
		}
		if el > 5*time.Second {
			slow = append(slow, line)
		}
		if *verbose {
			fmt.Println(line)
		}
		mu.Unlock()
	})
	el := time.Since(start)
	fmt.Printf("\n%d targets in %s (%.1f/s), inconsistent=%d\n", len(tg), el.Round(time.Millisecond), float64(len(tg))/el.Seconds(), incons)
	var ks []string
	for k := range counts {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Printf("  %-9s %d\n", k, counts[k])
	}
	fmt.Println("resolvers:")
	for _, s := range pool.Stats() {
		fmt.Printf("  %-22s %-10s q=%d fail=%d to=%d lat=%s benched=%v\n", s.Addr, s.Provider, s.Queries, s.Failures, s.Timeouts, s.AvgLatency.Round(time.Millisecond), s.Benched)
	}
	if len(slow) > 0 {
		fmt.Println("slow (>5s):")
		for _, s := range slow {
			fmt.Println("  " + s)
		}
	}
}

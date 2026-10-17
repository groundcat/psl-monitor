// Package dnscheck queries a pool of public recursive resolvers with
// load balancing, per-resolver rate limiting, health tracking, retries and
// cross-provider confirmation of negative answers.
package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// Result statuses.
const (
	StatusOK       = "ok"       // NS (or TXT) records present
	StatusNXDomain = "nxdomain" // name does not exist
	StatusNoData   = "nodata"   // name exists, no records of the type
	StatusServFail = "servfail" // resolvers could not resolve (lame / broken delegation)
	StatusTimeout  = "timeout"  // every attempt (>=2 providers) timed out
	StatusError    = "error"    // inconclusive (local / resolver problems)
)

// IsMissing reports whether a status counts as "records lost" for the
// expiry state machine. StatusError is inconclusive and is not counted.
func IsMissing(s string) bool {
	switch s {
	case StatusNXDomain, StatusNoData, StatusServFail, StatusTimeout:
		return true
	}
	return false
}

// Resolver is one upstream recursive resolver.
type Resolver struct {
	Addr     string // host:port
	Provider string // resolvers sharing a provider are not used to confirm each other

	lim       *rate.Limiter
	queries   atomic.Int64
	failures  atomic.Int64
	timeouts  atomic.Int64
	consecErr atomic.Int64
	benchedTo atomic.Int64 // unix nanos
	latencyNs atomic.Int64 // EWMA
}

// ResolverStats is a snapshot of resolver health.
type ResolverStats struct {
	Addr, Provider              string
	Queries, Failures, Timeouts int64
	AvgLatency                  time.Duration
	Benched                     bool
}

// Options configure a Pool.
type Options struct {
	Resolvers   []string // "ip[:port][@provider]"
	QPS         float64  // per resolver
	Timeout     time.Duration
	MaxAttempts int // attempts per lookup against distinct resolvers
}

// Pool load-balances queries across resolvers.
type Pool struct {
	res      []*Resolver
	timeout  time.Duration
	attempts int
	udp, tcp *dns.Client
}

// DefaultResolvers is used when none are configured.
var DefaultResolvers = []string{
	"1.1.1.1@cloudflare", "1.0.0.1@cloudflare",
	"8.8.8.8@google", "8.8.4.4@google",
	"9.9.9.9@quad9", "149.112.112.112@quad9",
	"208.67.222.222@opendns", "208.67.220.220@opendns",
}

// NewPool builds a resolver pool.
func NewPool(o Options) (*Pool, error) {
	if len(o.Resolvers) == 0 {
		o.Resolvers = DefaultResolvers
	}
	if o.QPS <= 0 {
		o.QPS = 20
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 4
	}
	p := &Pool{timeout: o.Timeout, attempts: o.MaxAttempts,
		udp: &dns.Client{Net: "udp", Timeout: o.Timeout, UDPSize: 1232},
		tcp: &dns.Client{Net: "tcp", Timeout: o.Timeout + 2*time.Second},
	}
	for _, s := range o.Resolvers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		prov := ""
		if i := strings.IndexByte(s, '@'); i >= 0 {
			s, prov = s[:i], s[i+1:]
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			host, port = s, "53"
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("resolver %q: not an IP address", s)
		}
		if prov == "" {
			prov = host
		}
		burst := int(o.QPS)
		if burst < 1 {
			burst = 1
		}
		p.res = append(p.res, &Resolver{Addr: net.JoinHostPort(host, port), Provider: prov,
			lim: rate.NewLimiter(rate.Limit(o.QPS), burst)})
	}
	if len(p.res) == 0 {
		return nil, errors.New("no resolvers configured")
	}
	return p, nil
}

// Stats returns a snapshot of resolver health.
func (p *Pool) Stats() []ResolverStats {
	now := time.Now().UnixNano()
	out := make([]ResolverStats, 0, len(p.res))
	for _, r := range p.res {
		out = append(out, ResolverStats{Addr: r.Addr, Provider: r.Provider,
			Queries: r.queries.Load(), Failures: r.failures.Load(), Timeouts: r.timeouts.Load(),
			AvgLatency: time.Duration(r.latencyNs.Load()), Benched: r.benchedTo.Load() > now})
	}
	return out
}

// pick chooses a healthy resolver, preferring providers not yet used.
// Selection is random among the best candidates (power of two choices on latency).
func (p *Pool) pick(excludeProv map[string]bool, excludeAddr map[string]bool) *Resolver {
	now := time.Now().UnixNano()
	var fresh, any []*Resolver
	for _, r := range p.res {
		if excludeAddr[r.Addr] {
			continue
		}
		if r.benchedTo.Load() > now {
			continue
		}
		any = append(any, r)
		if !excludeProv[r.Provider] {
			fresh = append(fresh, r)
		}
	}
	cands := fresh
	if len(cands) == 0 {
		cands = any
	}
	if len(cands) == 0 {
		// everything benched: fall back to any non-excluded resolver
		for _, r := range p.res {
			if !excludeAddr[r.Addr] {
				cands = append(cands, r)
			}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	a := cands[rand.IntN(len(cands))]
	b := cands[rand.IntN(len(cands))]
	if b.latencyNs.Load() < a.latencyNs.Load() {
		return b
	}
	return a
}

func (r *Resolver) observe(lat time.Duration, err error, timeout bool) {
	r.queries.Add(1)
	old := r.latencyNs.Load()
	if old == 0 {
		r.latencyNs.Store(int64(lat))
	} else {
		r.latencyNs.Store(old*7/8 + int64(lat)/8)
	}
	if err == nil {
		r.consecErr.Store(0)
		return
	}
	r.failures.Add(1)
	if timeout {
		r.timeouts.Add(1)
	}
	if n := r.consecErr.Add(1); n >= 8 {
		// bench for a while; doubles the latency penalty too
		r.benchedTo.Store(time.Now().Add(30 * time.Second).UnixNano())
		r.consecErr.Store(0)
	}
}

// Answer is a single resolver response.
type Answer struct {
	Resolver string
	Provider string
	Status   string
	Records  []string
	Err      string
	RTT      time.Duration
}

// exchange sends one query to one resolver.
func (p *Pool) exchange(ctx context.Context, r *Resolver, name string, qtype uint16) Answer {
	a := Answer{Resolver: r.Addr, Provider: r.Provider}
	if err := r.lim.Wait(ctx); err != nil {
		a.Status, a.Err = StatusError, "ratelimit wait: "+err.Error()
		return a
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	start := time.Now()
	resp, _, err := p.udp.ExchangeContext(ctx, m, r.Addr)
	if err == nil && resp != nil && resp.Truncated {
		resp, _, err = p.tcp.ExchangeContext(ctx, m, r.Addr)
	}
	a.RTT = time.Since(start)
	if err != nil {
		to := isTimeout(err)
		r.observe(a.RTT, err, to)
		if to {
			a.Status = StatusTimeout
		} else {
			a.Status = StatusError
		}
		a.Err = err.Error()
		return a
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		r.observe(a.RTT, nil, false)
		qn := strings.ToLower(dns.Fqdn(name))
		for _, rr := range resp.Answer {
			if !strings.EqualFold(rr.Header().Name, qn) {
				continue
			}
			switch v := rr.(type) {
			case *dns.NS:
				if qtype == dns.TypeNS {
					a.Records = append(a.Records, strings.TrimSuffix(strings.ToLower(v.Ns), "."))
				}
			case *dns.TXT:
				if qtype == dns.TypeTXT {
					a.Records = append(a.Records, strings.Join(v.Txt, ""))
				}
			}
		}
		if len(a.Records) > 0 {
			a.Status = StatusOK
			sort.Strings(a.Records)
			a.Records = dedup(a.Records)
		} else {
			a.Status = StatusNoData
		}
	case dns.RcodeNameError:
		r.observe(a.RTT, nil, false)
		a.Status = StatusNXDomain
	case dns.RcodeServerFailure:
		// SERVFAIL is an answer about the domain, not a resolver failure
		r.observe(a.RTT, nil, false)
		a.Status = StatusServFail
	default:
		// REFUSED / NOTIMP etc: resolver problem
		r.observe(a.RTT, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode]), false)
		a.Status = StatusError
		a.Err = "rcode " + dns.RcodeToString[resp.Rcode]
	}
	return a
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "i/o timeout")
}

func dedup(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Lookup is the consolidated result for one name.
type Lookup struct {
	Name         string
	Status       string
	Records      []string // union of records from all OK answers
	Answers      []Answer
	Inconsistent bool // resolvers disagreed (status or record set)
}

// Summary renders answers compactly for storage.
func (l *Lookup) Summary() string {
	var b strings.Builder
	for i, a := range l.Answers {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s=%s", a.Resolver, a.Status)
		if a.Status == StatusOK {
			fmt.Fprintf(&b, "(%d)", len(a.Records))
		}
		if a.Err != "" && a.Status != StatusTimeout {
			fmt.Fprintf(&b, "[%s]", a.Err)
		}
	}
	return b.String()
}

// Query resolves name/qtype with retries and confirmation:
//   - transport errors/timeouts are retried on other resolvers (other providers first)
//   - negative answers (nxdomain/nodata/servfail) are confirmed by a second provider;
//     any positive answer wins
//   - positive answers are optionally confirmed (confirmPositive) and unioned,
//     which smooths over resolvers returning partial NS sets
func (p *Pool) Query(ctx context.Context, name string, qtype uint16, confirmPositive func([]string) bool) *Lookup {
	l := &Lookup{Name: name}
	usedProv := map[string]bool{}
	usedAddr := map[string]bool{}
	timeoutProv := map[string]bool{}
	var negatives []Answer
	var positives []Answer
	for attempt := 0; attempt < p.attempts+1; attempt++ {
		if ctx.Err() != nil {
			break
		}
		// decide whether we need another query
		if len(positives) > 0 {
			if len(positives) >= 2 || confirmPositive == nil || !confirmPositive(positives[0].Records) {
				break
			}
		} else if len(negatives) >= 2 {
			break
		} else if attempt >= p.attempts {
			break
		}
		r := p.pick(usedProv, usedAddr)
		if r == nil {
			break
		}
		usedProv[r.Provider] = true
		usedAddr[r.Addr] = true
		a := p.exchange(ctx, r, name, qtype)
		l.Answers = append(l.Answers, a)
		switch a.Status {
		case StatusOK:
			positives = append(positives, a)
		case StatusNXDomain, StatusNoData, StatusServFail:
			negatives = append(negatives, a)
		case StatusTimeout:
			timeoutProv[a.Provider] = true
		}
	}
	switch {
	case len(positives) > 0:
		l.Status = StatusOK
		set := map[string]bool{}
		for _, a := range positives {
			for _, r := range a.Records {
				set[r] = true
			}
		}
		for r := range set {
			l.Records = append(l.Records, r)
		}
		sort.Strings(l.Records)
		if len(negatives) > 0 {
			l.Inconsistent = true
		}
		for _, a := range positives[1:] {
			if strings.Join(a.Records, ",") != strings.Join(positives[0].Records, ",") {
				l.Inconsistent = true
			}
		}
	case len(negatives) > 0:
		// majority by status; prefer the most "definitive" on ties
		cnt := map[string]int{}
		for _, a := range negatives {
			cnt[a.Status]++
		}
		best := ""
		for _, s := range []string{StatusNXDomain, StatusNoData, StatusServFail} {
			if cnt[s] > cnt[best] {
				best = s
			}
		}
		l.Status = best
		if len(cnt) > 1 {
			l.Inconsistent = true
		}
		if len(negatives) < 2 && len(timeoutProv) == 0 {
			// could not confirm with a second provider
			l.Status = StatusError
		}
	case len(timeoutProv) >= 2:
		l.Status = StatusTimeout
	default:
		l.Status = StatusError
	}
	return l
}

// QueryNS looks up NS records. When the observed set is disjoint from the
// known baseline, a second provider is consulted before accepting it.
func (p *Pool) QueryNS(ctx context.Context, name string, baseline []string) *Lookup {
	var confirm func([]string) bool
	if len(baseline) > 0 {
		confirm = func(got []string) bool { return !Overlaps(got, baseline) }
	}
	return p.Query(ctx, name, dns.TypeNS, confirm)
}

// QueryTXT looks up TXT records.
func (p *Pool) QueryTXT(ctx context.Context, name string) *Lookup {
	return p.Query(ctx, name, dns.TypeTXT, nil)
}

// Overlaps reports whether two NS sets share at least one host.
func Overlaps(a, b []string) bool {
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[normNS(x)] = true
	}
	for _, y := range b {
		if set[normNS(y)] {
			return true
		}
	}
	return false
}

func normNS(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }

// Runner executes fn over items with bounded concurrency. fn must respect ctx.
func Runner[T any](ctx context.Context, workers int, items []T, fn func(context.Context, T)) {
	if workers < 1 {
		workers = 1
	}
	ch := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				fn(ctx, it)
			}
		}()
	}
	for _, it := range items {
		select {
		case ch <- it:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(ch)
	wg.Wait()
}

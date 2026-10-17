// Package rdap is a small RDAP domain client with IANA bootstrap, per-host
// throttling, Retry-After handling and a per-host circuit breaker.
package rdap

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

//go:embed bootstrap_dns.json
var embeddedBootstrap []byte

const (
	BootstrapURL = "https://data.iana.org/rdap/dns.json"
	IANABase     = "https://rdap.iana.org/"
)

// Result values.
const (
	ResultFound       = "found"
	ResultNotFound    = "not_found"
	ResultUnsupported = "unsupported" // no RDAP server known for the TLD
	ResultError       = "error"       // server error / timeout / throttled
)

// Domain is the parsed subset of an RDAP domain object.
type Domain struct {
	Result      string
	Server      string
	Created     time.Time
	Expires     time.Time
	LastChanged time.Time
	Statuses    []string
	Nameservers []string
	Registrar   string
	HTTPStatus  int
	Err         string
	Elapsed     time.Duration
}

type hostState struct {
	sem        chan struct{}
	lim        *rate.Limiter
	mu         sync.Mutex
	consecFail int
	openUntil  time.Time
	requests   int64
	failures   int64
	throttled  int64
}

// HostStats reports per-server health.
type HostStats struct {
	Host                          string
	Requests, Failures, Throttled int64
	CircuitOpen                   bool
}

// Client is safe for concurrent use.
type Client struct {
	http        *http.Client
	mu          sync.RWMutex
	servers     map[string]string // tld -> base URL (with trailing slash)
	overrides   map[string]string
	hosts       sync.Map // host -> *hostState
	perHostConc int
	perHostQPS  float64
	UserAgent   string
}

// Options configures a Client.
type Options struct {
	Timeout     time.Duration
	PerHostConc int
	PerHostQPS  float64
	Overrides   map[string]string // tld -> base URL, takes precedence over bootstrap
}

// New creates a client using the embedded bootstrap.
func New(o Options) *Client {
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.PerHostConc <= 0 {
		o.PerHostConc = 4
	}
	if o.PerHostQPS <= 0 {
		o.PerHostQPS = 4
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   6 * time.Second,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: o.Timeout,
	}
	c := &Client{
		http:        &http.Client{Timeout: o.Timeout, Transport: tr},
		servers:     map[string]string{},
		overrides:   map[string]string{},
		perHostConc: o.PerHostConc,
		perHostQPS:  o.PerHostQPS,
		UserAgent:   "psl-monitor/1.0 (+https://publicsuffix.org)",
	}
	_ = c.LoadBootstrap(embeddedBootstrap)
	c.SetOverrides(o.Overrides)
	return c
}

// LoadBootstrap loads an IANA dns.json bootstrap document.
func (c *Client) LoadBootstrap(b []byte) error {
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	m := map[string]string{}
	for _, s := range doc.Services {
		if len(s) < 2 || len(s[1]) == 0 {
			continue
		}
		base := s[1][0]
		for _, u := range s[1] {
			if strings.HasPrefix(u, "https://") {
				base = u
				break
			}
		}
		if !strings.HasSuffix(base, "/") {
			base += "/"
		}
		for _, t := range s[0] {
			m[strings.ToLower(t)] = base
		}
	}
	if len(m) < 50 {
		return fmt.Errorf("bootstrap too small (%d)", len(m))
	}
	c.mu.Lock()
	c.servers = m
	c.mu.Unlock()
	return nil
}

// RefreshBootstrap downloads the IANA bootstrap file.
func (c *Client) RefreshBootstrap(ctx context.Context) (int, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", BootstrapURL, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, err
	}
	if err := c.LoadBootstrap(b); err != nil {
		return 0, err
	}
	return c.TLDCount(), nil
}

// SetOverrides replaces manual TLD -> server mappings.
func (c *Client) SetOverrides(o map[string]string) {
	m := map[string]string{}
	for k, v := range o {
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		if !strings.HasSuffix(v, "/") {
			v += "/"
		}
		m[k] = v
	}
	c.mu.Lock()
	c.overrides = m
	c.mu.Unlock()
}

// TLDCount returns the number of TLDs with a known server.
func (c *Client) TLDCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := len(c.servers)
	for k := range c.overrides {
		if _, ok := c.servers[k]; !ok {
			n++
		}
	}
	return n
}

// ServerFor returns the RDAP base URL for a domain ("" if unsupported).
// Single-label names (TLDs) are looked up at IANA.
func (c *Client) ServerFor(domain string) string {
	if !strings.Contains(domain, ".") {
		return IANABase
	}
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	c.mu.RLock()
	defer c.mu.RUnlock()
	if s, ok := c.overrides[tld]; ok {
		return s
	}
	return c.servers[tld]
}

func (c *Client) host(base string) *hostState {
	u, err := url.Parse(base)
	h := base
	if err == nil {
		h = u.Host
	}
	if v, ok := c.hosts.Load(h); ok {
		return v.(*hostState)
	}
	hs := &hostState{sem: make(chan struct{}, c.perHostConc), lim: rate.NewLimiter(rate.Limit(c.perHostQPS), 1)}
	v, _ := c.hosts.LoadOrStore(h, hs)
	return v.(*hostState)
}

// Stats returns per-host stats.
func (c *Client) Stats() []HostStats {
	var out []HostStats
	now := time.Now()
	c.hosts.Range(func(k, v any) bool {
		h := v.(*hostState)
		h.mu.Lock()
		out = append(out, HostStats{Host: k.(string), Requests: h.requests, Failures: h.failures, Throttled: h.throttled, CircuitOpen: h.openUntil.After(now)})
		h.mu.Unlock()
		return true
	})
	return out
}

// ResetCircuits closes all breakers (e.g. at the start of a run).
func (c *Client) ResetCircuits() {
	c.hosts.Range(func(_, v any) bool {
		h := v.(*hostState)
		h.mu.Lock()
		h.consecFail, h.openUntil = 0, time.Time{}
		h.mu.Unlock()
		return true
	})
}

var errCircuitOpen = errors.New("circuit open: server repeatedly failing")

// Lookup queries RDAP for a domain. It never blocks longer than ctx allows.
func (c *Client) Lookup(ctx context.Context, domain string) *Domain {
	start := time.Now()
	d := &Domain{}
	base := c.ServerFor(domain)
	if base == "" {
		d.Result = ResultUnsupported
		return d
	}
	d.Server = base
	hs := c.host(base)
	defer func() { d.Elapsed = time.Since(start) }()

	for attempt := 0; attempt < 3; attempt++ {
		hs.mu.Lock()
		open := hs.openUntil.After(time.Now())
		hs.mu.Unlock()
		if open {
			d.Result, d.Err = ResultError, errCircuitOpen.Error()
			return d
		}
		select {
		case hs.sem <- struct{}{}:
		case <-ctx.Done():
			d.Result, d.Err = ResultError, ctx.Err().Error()
			return d
		}
		err := hs.lim.Wait(ctx)
		var retryAfter time.Duration
		var done bool
		if err == nil {
			retryAfter, done, err = c.do(ctx, base, domain, d, hs)
		}
		<-hs.sem
		if done {
			return d
		}
		d.Result = ResultError
		if err != nil {
			d.Err = err.Error()
		}
		if ctx.Err() != nil {
			return d
		}
		if retryAfter <= 0 {
			retryAfter = time.Duration(attempt+1) * 2 * time.Second
		}
		if retryAfter > 30*time.Second {
			// don't let a single server stall the run
			return d
		}
		select {
		case <-time.After(retryAfter):
		case <-ctx.Done():
			return d
		}
	}
	return d
}

// do performs one request. done=true means d holds a definitive answer.
func (c *Client) do(ctx context.Context, base, domain string, d *Domain, hs *hostState) (time.Duration, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"domain/"+url.PathEscape(domain), nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.http.Do(req)
	hs.mu.Lock()
	hs.requests++
	hs.mu.Unlock()
	if err != nil {
		c.fail(hs, false)
		return 0, false, err
	}
	defer resp.Body.Close()
	d.HTTPStatus = resp.StatusCode
	switch {
	case resp.StatusCode == 404:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		c.ok(hs)
		d.Result = ResultNotFound
		return 0, true, nil
	case resp.StatusCode == 429 || resp.StatusCode == 503:
		c.fail(hs, true)
		ra := parseRetryAfter(resp.Header.Get("Retry-After"))
		return ra, false, fmt.Errorf("HTTP %d (throttled)", resp.StatusCode)
	case resp.StatusCode >= 400:
		c.fail(hs, false)
		if resp.StatusCode == 400 || resp.StatusCode == 403 || resp.StatusCode == 422 || resp.StatusCode == 501 {
			// not retryable
			d.Result, d.Err = ResultError, fmt.Sprintf("HTTP %d", resp.StatusCode)
			return 0, true, nil
		}
		return 0, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		c.fail(hs, false)
		return 0, false, err
	}
	if err := parseDomain(b, d); err != nil {
		c.fail(hs, false)
		d.Result, d.Err = ResultError, "parse: "+err.Error()
		return 0, true, nil
	}
	c.ok(hs)
	d.Result = ResultFound
	return 0, true, nil
}

func (c *Client) ok(hs *hostState) {
	hs.mu.Lock()
	hs.consecFail = 0
	hs.mu.Unlock()
}

func (c *Client) fail(hs *hostState, throttled bool) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.failures++
	if throttled {
		hs.throttled++
	}
	hs.consecFail++
	if hs.consecFail >= 6 {
		hs.openUntil = time.Now().Add(5 * time.Minute)
		hs.consecFail = 0
	}
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

type rdapDoc struct {
	ObjectClassName string   `json:"objectClassName"`
	LDHName         string   `json:"ldhName"`
	Status          []string `json:"status"`
	Events          []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []struct {
		Roles      []string        `json:"roles"`
		VCardArray json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
	ErrorCode int `json:"errorCode"`
}

func parseDomain(b []byte, d *Domain) error {
	var doc rdapDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	if doc.ErrorCode == 404 {
		d.Result = ResultNotFound
		return nil
	}
	for _, e := range doc.Events {
		t := parseTime(e.Date)
		if t.IsZero() {
			continue
		}
		switch strings.ToLower(e.Action) {
		case "registration":
			d.Created = t
		case "expiration":
			d.Expires = t
		case "last changed":
			d.LastChanged = t
		}
	}
	d.Statuses = doc.Status
	for _, n := range doc.Nameservers {
		if n.LDHName != "" {
			d.Nameservers = append(d.Nameservers, strings.ToLower(strings.TrimSuffix(n.LDHName, ".")))
		}
	}
	for _, e := range doc.Entities {
		for _, r := range e.Roles {
			if r == "registrar" {
				d.Registrar = vcardFN(e.VCardArray)
			}
		}
	}
	return nil
}

func vcardFN(raw json.RawMessage) string {
	var v []any
	if json.Unmarshal(raw, &v) != nil || len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		pa, _ := p.([]any)
		if len(pa) >= 4 && pa[0] == "fn" {
			if s, ok := pa[3].(string); ok {
				return s
			}
		}
	}
	return ""
}

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, f := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04:05Z0700", "2006-01-02"} {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

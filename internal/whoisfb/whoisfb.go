// Package whoisfb is the WHOIS / web-WHOIS fallback used when RDAP is not
// available or fails. It calls the JSON API of reg233/whois-domain-lookup
// (vendored as a git submodule under third_party/ and run as a sidecar
// service), which carries maintained WHOIS server lists, web-based lookups
// and per-ccTLD parsers.
package whoisfb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Result values (mirroring rdap.Result*).
const (
	ResultFound       = "found"
	ResultNotFound    = "not_found"
	ResultReserved    = "reserved"
	ResultUnsupported = "unsupported" // upstream knows no WHOIS server for the TLD
	ResultError       = "error"
)

// Domain is the normalised fallback answer.
type Domain struct {
	Result      string
	Source      string // always "whois" (port 43 or web-based, decided upstream)
	Server      string // registry WHOIS server (when reported)
	Created     time.Time
	Expires     time.Time
	Updated     time.Time
	Statuses    []string
	Nameservers []string
	Registrar   string
	Err         string
	Elapsed     time.Duration
}

// Options configures a Client.
type Options struct {
	BaseURL  string        // e.g. http://whois:80  ("" disables the fallback)
	Password string        // upstream SITE_PASSWORD, if set
	Timeout  time.Duration // per request
	// Concurrency and QPS bound load per TLD: WHOIS servers rate-limit
	// aggressively and some block clients outright.
	PerTLDConc int
	PerTLDQPS  float64
	MaxConc    int
}

// Client is safe for concurrent use.
type Client struct {
	base   string
	auth   string
	http   *http.Client
	o      Options
	global chan struct{}
	tlds   sync.Map // tld -> *tldState

	mu       sync.Mutex
	requests int64
	failures int64
}

type tldState struct {
	sem chan struct{}
	lim *rate.Limiter
}

// New returns a client, or nil when BaseURL is empty (fallback disabled).
func New(o Options) *Client {
	if strings.TrimSpace(o.BaseURL) == "" {
		return nil
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.PerTLDConc <= 0 {
		o.PerTLDConc = 2
	}
	if o.PerTLDQPS <= 0 {
		o.PerTLDQPS = 1
	}
	if o.MaxConc <= 0 {
		o.MaxConc = 16
	}
	c := &Client{
		base:   strings.TrimRight(strings.TrimSpace(o.BaseURL), "/"),
		http:   &http.Client{Timeout: o.Timeout, Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, MaxIdleConnsPerHost: o.MaxConc}},
		o:      o,
		global: make(chan struct{}, o.MaxConc),
	}
	if o.Password != "" {
		h := sha256.Sum256([]byte(o.Password))
		c.auth = "Bearer " + hex.EncodeToString(h[:])
	}
	return c
}

// Enabled reports whether the fallback is configured.
func (c *Client) Enabled() bool { return c != nil }

// BaseURL returns the service URL.
func (c *Client) BaseURL() string {
	if c == nil {
		return ""
	}
	return c.base
}

// Stats returns request counters.
func (c *Client) Stats() (requests, failures int64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, c.failures
}

func (c *Client) tld(name string) *tldState {
	t := name
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		t = name[i+1:]
	}
	if v, ok := c.tlds.Load(t); ok {
		return v.(*tldState)
	}
	v, _ := c.tlds.LoadOrStore(t, &tldState{sem: make(chan struct{}, c.o.PerTLDConc), lim: rate.NewLimiter(rate.Limit(c.o.PerTLDQPS), 1)})
	return v.(*tldState)
}

// apiResponse is the upstream envelope: {"code":0,"msg":"...","data":{...}}.
type apiResponse struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// apiData is the subset of the upstream Parser object we use.
type apiData struct {
	Unknown             bool    `json:"unknown"`
	Reserved            bool    `json:"reserved"`
	Registered          bool    `json:"registered"`
	Domain              string  `json:"domain"`
	RegistryWHOISServer string  `json:"registryWHOISServer"`
	Registrar           string  `json:"registrar"`
	CreationDate        *string `json:"creationDateISO8601"`
	ExpirationDate      *string `json:"expirationDateISO8601"`
	UpdatedDate         *string `json:"updatedDateISO8601"`
	Status              []struct {
		Text string `json:"text"`
	} `json:"status"`
	NameServers      []string `json:"nameServers"`
	PendingDelete    bool     `json:"pendingDelete"`
	RedemptionPeriod bool     `json:"redemptionPeriod"`
	Hold             bool     `json:"hold"`
}

// Lookup queries the WHOIS fallback for a domain. RDAP is deliberately not
// requested from upstream: the caller already tried RDAP itself.
func (c *Client) Lookup(ctx context.Context, domain string) *Domain {
	start := time.Now()
	d := &Domain{Source: "whois"}
	defer func() { d.Elapsed = time.Since(start) }()
	ts := c.tld(domain)
	for _, ch := range []chan struct{}{c.global, ts.sem} {
		select {
		case ch <- struct{}{}:
			defer func(ch chan struct{}) { <-ch }(ch)
		case <-ctx.Done():
			d.Result, d.Err = ResultError, ctx.Err().Error()
			return d
		}
	}
	if err := ts.lim.Wait(ctx); err != nil {
		d.Result, d.Err = ResultError, err.Error()
		return d
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		res, err := c.do(ctx, domain, d)
		if err == nil {
			d.Result = res
			return d
		}
		lastErr = err
		if ctx.Err() != nil || !retryable(err) {
			break
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
	}
	d.Result, d.Err = ResultError, lastErr.Error()
	return d
}

// upstreamError is a lookup error reported by the service (WHOIS server
// refused, timed out, ...). Only transient-looking ones are retried.
type upstreamError struct{ msg string }

func (e *upstreamError) Error() string { return e.msg }

// transportError wraps failures talking to the service itself.
type transportError struct{ error }

func retryable(err error) bool {
	var ue *upstreamError
	if errors.As(err, &ue) {
		m := strings.ToLower(ue.msg)
		return strings.Contains(m, "timed out") || strings.Contains(m, "failed to read") || strings.Contains(m, "unreachable")
	}
	var te transportError
	return errors.As(err, &te)
}

func (c *Client) do(ctx context.Context, domain string, d *Domain) (string, error) {
	q := url.Values{"domain": {domain}, "whois": {"1"}, "json": {"1"}}
	// src/index.php is reachable regardless of web server rewrite rules.
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+"/src/index.php?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	if c.auth != "" {
		req.Header.Set("Authorization", c.auth)
	}
	resp, err := c.http.Do(req)
	c.mu.Lock()
	c.requests++
	c.mu.Unlock()
	if err != nil {
		c.fail()
		return "", transportError{err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		c.fail()
		return "", err
	}
	if resp.StatusCode != 200 {
		c.fail()
		err := fmt.Errorf("whois service HTTP %d", resp.StatusCode)
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			return "", transportError{err}
		}
		return "", err
	}
	return parse(body, d, c.fail)
}

func (c *Client) fail() {
	c.mu.Lock()
	c.failures++
	c.mu.Unlock()
}

// parse converts an upstream JSON response into d and returns the result.
func parse(body []byte, d *Domain, onFail func()) (string, error) {
	var r apiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		onFail()
		return "", fmt.Errorf("whois service: invalid JSON: %v", err)
	}
	if r.Code != 0 {
		if strings.HasPrefix(r.Msg, "No WHOIS server found") || strings.HasPrefix(r.Msg, "No WHOIS or RDAP server found") {
			return ResultUnsupported, nil
		}
		if strings.Contains(r.Msg, "Incorrect password") {
			onFail()
			return "", errors.New("whois service rejected credentials (check WHOIS_FALLBACK_PASSWORD)")
		}
		onFail()
		return "", &upstreamError{msg: r.Msg}
	}
	var a apiData
	if err := json.Unmarshal(r.Data, &a); err != nil {
		onFail()
		return "", fmt.Errorf("whois service: invalid data: %v", err)
	}
	d.Server = a.RegistryWHOISServer
	switch {
	case a.Unknown:
		onFail()
		return "", errors.New("whois service returned no data")
	case a.Reserved:
		return ResultReserved, nil
	case !a.Registered:
		return ResultNotFound, nil
	}
	d.Created = parseTime(a.CreationDate)
	d.Expires = parseTime(a.ExpirationDate)
	d.Updated = parseTime(a.UpdatedDate)
	d.Registrar = a.Registrar
	seen := map[string]bool{}
	for _, n := range a.NameServers {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n != "" && !seen[n] {
			seen[n] = true
			d.Nameservers = append(d.Nameservers, n)
		}
	}
	for _, s := range a.Status {
		if t := strings.TrimSpace(s.Text); t != "" {
			d.Statuses = append(d.Statuses, t)
		}
	}
	// Upstream normalises these across registries; surface them as RDAP-style
	// statuses so flag evaluation treats both sources the same.
	if a.PendingDelete {
		d.Statuses = append(d.Statuses, "pending delete")
	}
	if a.RedemptionPeriod {
		d.Statuses = append(d.Statuses, "redemption period")
	}
	if a.Hold {
		d.Statuses = append(d.Statuses, "server hold")
	}
	return ResultFound, nil
}

func parseTime(p *string) time.Time {
	if p == nil {
		return time.Time{}
	}
	s := strings.TrimSpace(*p)
	for _, f := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC().Truncate(time.Second)
		}
	}
	return time.Time{}
}

// ExtraRDAPServers fetches the upstream's community-maintained list of RDAP
// servers missing from the IANA bootstrap (src/data/rdap-servers-extra.json).
func (c *Client) ExtraRDAPServers(ctx context.Context) ([]byte, error) {
	if c == nil {
		return nil, errors.New("disabled")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/src/data/rdap-servers-extra.json", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, errors.New("invalid JSON")
	}
	return b, nil
}

var reVersion = regexp.MustCompile(`v\d{4}\.\d{1,2}\.\d{1,2}`)

// Version returns the upstream release version reported by the running
// service (parsed from its HTML footer), or "" if unknown.
func (c *Client) Version(ctx context.Context) string {
	if c == nil {
		return ""
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/src/index.php", nil)
	if c.auth != "" {
		req.Header.Set("Authorization", c.auth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return reVersion.FindString(string(b))
}

// Ping checks the service is reachable (used by the UI and startup log).
func (c *Client) Ping(ctx context.Context) error {
	if c == nil {
		return errors.New("disabled")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/src/index.php?json=1", nil)
	if c.auth != "" {
		req.Header.Set("Authorization", c.auth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var r apiResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return fmt.Errorf("unexpected response: %v", err)
	}
	if strings.Contains(r.Msg, "Incorrect password") {
		return errors.New("credentials rejected")
	}
	return nil // "The 'domain' parameter is required." means it's alive
}

// Package settings defines admin-editable runtime settings stored in the db.
package settings

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/checker"
	"psl-monitor/internal/compliance"
	"psl-monitor/internal/dnscheck"
	"psl-monitor/internal/store"
)

// Def is one editable setting.
type Def struct {
	Key     string
	Label   string
	Default string
	Help    string
	Kind    string // int, text, textarea, bool
	Min     int
	Max     int
}

var Defs = []Def{
	{Key: "psl_url", Label: "PSL URL", Default: "https://publicsuffix.org/list/public_suffix_list.dat", Kind: "text"},
	{Key: "exceptions_url", Label: "Exceptions source URL", Default: compliance.DefaultExceptionsURL, Kind: "text", Help: "Go source containing missingTXT; refreshed on demand from the TXT page"},
	{Key: "grace_days", Label: "Grace period (distinct days)", Default: "5", Kind: "int", Min: 1, Max: 60, Help: "NS must be missing / replaced on this many distinct days before flagging as defunct / changed"},
	{Key: "dns_workers", Label: "DNS concurrency", Default: "64", Kind: "int", Min: 1, Max: 512},
	{Key: "dns_qps", Label: "Per-resolver QPS", Default: "25", Kind: "int", Min: 1, Max: 500},
	{Key: "dns_timeout_ms", Label: "DNS query timeout (ms)", Default: "2500", Kind: "int", Min: 300, Max: 15000},
	{Key: "dns_attempts", Label: "DNS attempts per lookup", Default: "4", Kind: "int", Min: 2, Max: 8, Help: "Attempts across distinct resolvers; negative answers are confirmed by a second provider"},
	{Key: "target_timeout_s", Label: "Per-target deadline (s)", Default: "20", Kind: "int", Min: 3, Max: 120},
	{Key: "resolvers", Label: "Resolvers", Default: strings.Join(dnscheck.DefaultResolvers, "\n"), Kind: "textarea", Help: "One per line: ip[:port][@provider]. Resolvers sharing a provider don't confirm each other"},
	{Key: "rdap_workers", Label: "RDAP concurrency", Default: "32", Kind: "int", Min: 1, Max: 256},
	{Key: "rdap_host_conc", Label: "RDAP per-server concurrency", Default: "3", Kind: "int", Min: 1, Max: 32},
	{Key: "rdap_host_qps", Label: "RDAP per-server QPS", Default: "3", Kind: "int", Min: 1, Max: 50},
	{Key: "rdap_overrides", Label: "RDAP server overrides", Default: "", Kind: "textarea", Help: "One per line: tld=https://rdap.example/ (for ccTLDs missing from the IANA bootstrap)"},
	{Key: "auto_rdap", Label: "Auto RDAP-confirm DNS anomalies", Default: "1", Kind: "bool"},
	{Key: "rdap_max_age_days", Label: "RDAP cache max age for anomalies (days)", Default: "3", Kind: "int", Min: 1, Max: 365},
	{Key: "parking_ns", Label: "Parking nameservers", Default: analyze.DefaultParkingNS, Kind: "textarea", Help: "Exact NS hosts; their parent domains also match unless generic"},
	{Key: "parking_keywords", Label: "Parking NS keywords", Default: strings.Join(analyze.DefaultParkingKeywords, "\n"), Kind: "textarea"},
	{Key: "retention_days", Label: "History retention (days)", Default: "365", Kind: "int", Min: 7, Max: 3650},
}

// Get returns a setting with its default.
func Get(st *store.Store, key string) string {
	for _, d := range Defs {
		if d.Key == key {
			return st.GetSetting(key, d.Default)
		}
	}
	return st.GetSetting(key, "")
}

func Int(st *store.Store, key string) int {
	n, _ := strconv.Atoi(Get(st, key))
	return n
}

// Validate checks a submitted value.
func Validate(d Def, v string) (string, error) {
	v = strings.TrimSpace(strings.ReplaceAll(v, "\r\n", "\n"))
	switch d.Kind {
	case "int":
		n, err := strconv.Atoi(v)
		if err != nil || n < d.Min || n > d.Max {
			return "", fmt.Errorf("%s: must be an integer in [%d, %d]", d.Label, d.Min, d.Max)
		}
	case "bool":
		if v != "1" {
			v = "0"
		}
	}
	if d.Key == "resolvers" {
		if _, err := dnscheck.NewPool(dnscheck.Options{Resolvers: Lines(v)}); err != nil {
			return "", err
		}
	}
	return v, nil
}

// Lines splits a textarea into trimmed non-empty, non-comment lines.
func Lines(v string) []string {
	var out []string
	for _, l := range strings.Split(v, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// Overrides parses "tld=url" lines.
func Overrides(v string) map[string]string {
	m := map[string]string{}
	for _, l := range Lines(v) {
		k, u, ok := strings.Cut(l, "=")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(u)
		}
	}
	return m
}

// CheckerConfig builds the checker config from settings.
func CheckerConfig(st *store.Store) checker.Config {
	return checker.Config{
		PSLURL:        Get(st, "psl_url"),
		ExceptionsURL: Get(st, "exceptions_url"),
		Grace:         Int(st, "grace_days"),
		DNSWorkers:    Int(st, "dns_workers"),
		RDAPWorkers:   Int(st, "rdap_workers"),
		TXTWorkers:    Int(st, "dns_workers"),
		TargetTimeout: time.Duration(Int(st, "target_timeout_s")) * time.Second,
		RDAPMaxAge:    time.Duration(Int(st, "rdap_max_age_days")) * 24 * time.Hour,
		AutoRDAP:      Get(st, "auto_rdap") == "1",
	}
}

// DNSPool builds a resolver pool from settings.
func DNSPool(st *store.Store) (*dnscheck.Pool, error) {
	return dnscheck.NewPool(dnscheck.Options{
		Resolvers:   Lines(Get(st, "resolvers")),
		QPS:         float64(Int(st, "dns_qps")),
		Timeout:     time.Duration(Int(st, "dns_timeout_ms")) * time.Millisecond,
		MaxAttempts: Int(st, "dns_attempts"),
	})
}

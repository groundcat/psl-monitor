package analyze

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity levels (higher = worse).
const (
	SevNone     = 0
	SevInfo     = 1
	SevLow      = 2
	SevMedium   = 3
	SevHigh     = 4
	SevCritical = 5
)

var SevNames = map[int]string{SevNone: "ok", SevInfo: "info", SevLow: "low", SevMedium: "medium", SevHigh: "high", SevCritical: "critical"}

// Confidence levels.
const (
	ConfConfirmed = "confirmed"
	ConfHigh      = "high"
	ConfMedium    = "medium"
	ConfLow       = "low"
)

// Flag types.
const (
	FlagExpired         = "expired"          // RDAP expiry date in the past
	FlagDropped         = "dropped"          // RDAP: domain not found (deleted / available)
	FlagRDAPVanished    = "rdap_vanished"    // RDAP record existed before, now 404
	FlagReRegistered    = "re_registered"    // RDAP creation date changed (new registration)
	FlagPendingDelete   = "pending_delete"   // RDAP status: pending delete / redemption
	FlagHold            = "hold"             // RDAP status: client/server hold
	FlagDefunct         = "defunct"          // NS missing >= grace days after having NS
	FlagNSMissing       = "ns_missing"       // NS missing, within grace period
	FlagChanged         = "ns_changed"       // NS fully replaced for >= grace days (changed hands?)
	FlagChanging        = "ns_changing"      // NS fully replaced, within grace period
	FlagParked          = "parked"           // current NS looks like a parking/expiry service
	FlagAppeared        = "ns_appeared"      // previously undelegated name now delegated
	FlagNeverResolved   = "never_resolved"   // private: no NS since monitoring began
	FlagExpiringSoon    = "expiring_soon"    // RDAP expiry within 30 days
	FlagExpiring90      = "expiring_90d"     // RDAP expiry within 90 days
	FlagShortTerm       = "short_term"       // private: expiry < 1 year away (PSL requires >1y)
	FlagNewlyRegistered = "newly_registered" // RDAP creation within the last year
	FlagTXTMissing      = "psl_txt_missing"  // private rule(s) lacking _psl TXT and not exempt
	FlagInconsistent    = "inconsistent"     // resolvers disagree
)

// FlagTypes is the ordered list for UI filters.
var FlagTypes = []string{FlagExpired, FlagDropped, FlagRDAPVanished, FlagReRegistered, FlagPendingDelete, FlagHold,
	FlagDefunct, FlagNSMissing, FlagNeverResolved, FlagChanged, FlagChanging, FlagParked, FlagAppeared,
	FlagExpiringSoon, FlagExpiring90, FlagShortTerm, FlagNewlyRegistered, FlagTXTMissing, FlagInconsistent}

// FlagHelp describes each flag for the UI.
var FlagHelp = map[string]string{
	FlagExpired:         "RDAP expiration date is in the past",
	FlagDropped:         "RDAP says the domain does not exist (deleted / available for registration)",
	FlagRDAPVanished:    "RDAP previously returned a record, now returns 404",
	FlagReRegistered:    "RDAP creation date differs from the cached one: domain was re-registered",
	FlagPendingDelete:   "RDAP status indicates redemption / pending delete",
	FlagHold:            "RDAP status indicates client/server hold (not in zone)",
	FlagDefunct:         "Had NS records, now missing (NXDOMAIN/SERVFAIL/NODATA/timeout) for the full grace period",
	FlagNSMissing:       "Had NS records, currently missing; inside grace period",
	FlagChanged:         "NS set is completely disjoint from baseline for the full grace period (possible change of hands)",
	FlagChanging:        "NS set is disjoint from baseline; inside grace period",
	FlagParked:          "NS hostnames match known parking / expiry nameservers or keywords",
	FlagAppeared:        "Name was observed undelegated on several days and is now delegated",
	FlagNeverResolved:   "Private registrable domain has had no NS records since monitoring began (broken before tracking started)",
	FlagExpiringSoon:    "RDAP expiration within 30 days",
	FlagExpiring90:      "RDAP expiration within 90 days",
	FlagShortTerm:       "Private entry with less than 1 year of registration left (PSL expects >1 year)",
	FlagNewlyRegistered: "RDAP creation date within the last 365 days",
	FlagTXTMissing:      "Private rule lacks a _psl TXT record and is not in the exemption list",
	FlagInconsistent:    "Resolvers returned differing answers on the last check",
}

// Flag is one finding.
type Flag struct {
	Type       string `json:"type"`
	Severity   int    `json:"sev"`
	Confidence string `json:"conf"`
	Msg        string `json:"msg"`
}

// RDAPInfo is the cached RDAP view of a target.
type RDAPInfo struct {
	Result      string // found, not_found, unsupported, error, "" (never checked)
	Created     time.Time
	Expires     time.Time
	PrevCreated time.Time // creation date seen before the latest one (if different)
	Statuses    []string
	EverFound   bool
	CheckedAt   time.Time
}

// TXTInfo summarises _psl compliance across a target's private rules.
type TXTInfo struct {
	Checked int
	Missing []string // non-exempt rule names lacking _psl
}

// Input is everything evaluation needs.
type Input struct {
	Section  string // icann / private
	DNS      NSState
	RDAP     RDAPInfo
	TXT      TXTInfo
	ParkedNS []string // NS hosts matching parking patterns
	Grace    int
	Now      time.Time
}

// Evaluate produces flags, sorted by severity descending.
func Evaluate(in Input) []Flag {
	var f []Flag
	add := func(t string, sev int, conf, msg string, a ...any) {
		f = append(f, Flag{Type: t, Severity: sev, Confidence: conf, Msg: fmt.Sprintf(msg, a...)})
	}
	priv := in.Section == "private"
	d := in.DNS
	r := in.RDAP
	now := in.Now
	dnsBad := d.State == DNSDefunct || d.State == DNSMissing
	dnsChanged := d.State == DNSChanged || d.State == DNSChanging

	// --- RDAP-based findings
	rdapExpired := false
	if r.Result == "found" && !r.Expires.IsZero() && r.Expires.Before(now) {
		rdapExpired = true
		days := int(now.Sub(r.Expires).Hours() / 24)
		sev := SevHigh
		switch {
		case dnsBad || dnsChanged || len(in.ParkedNS) > 0:
			sev = SevCritical
		case !priv && d.State == DNSNoNS:
			// registry placeholder object for a label that isn't delegated: stale
			// registry data, worth a look but not alarming
			sev = SevMedium
		}
		add(FlagExpired, sev, ConfConfirmed, "RDAP expiry %s (%d days ago)", r.Expires.Format("2006-01-02"), days)
	}
	if r.Result == "not_found" {
		switch {
		case priv:
			add(FlagDropped, SevCritical, ConfConfirmed, "registry RDAP returns 404: domain not registered")
		case r.EverFound:
			add(FlagDropped, SevCritical, ConfHigh, "registry RDAP returns 404 for a suffix it previously knew")
		}
		if r.EverFound && priv {
			add(FlagRDAPVanished, SevCritical, ConfConfirmed, "RDAP record existed previously and is now gone")
		}
	}
	if r.Result == "found" && !r.PrevCreated.IsZero() && !r.Created.IsZero() &&
		r.PrevCreated.UTC().Format("2006-01-02") != r.Created.UTC().Format("2006-01-02") {
		add(FlagReRegistered, SevCritical, ConfHigh, "creation date changed %s -> %s", r.PrevCreated.Format("2006-01-02"), r.Created.Format("2006-01-02"))
	}
	for _, st := range r.Statuses {
		s := strings.ToLower(strings.ReplaceAll(st, " ", ""))
		switch {
		case strings.Contains(s, "pendingdelete") || strings.Contains(s, "redemptionperiod") || strings.Contains(s, "pendingrestore"):
			add(FlagPendingDelete, SevCritical, ConfConfirmed, "RDAP status %q", st)
		case strings.HasSuffix(s, "hold") && (strings.HasPrefix(s, "client") || strings.HasPrefix(s, "server")):
			// For ICANN suffixes a registry-reserved, undelegated label on hold is
			// a common, intentional setup; it only matters if it was delegated before.
			if priv || d.State == DNSDefunct || d.State == DNSMissing {
				add(FlagHold, SevHigh, ConfConfirmed, "RDAP status %q", st)
			} else {
				add(FlagHold, SevLow, ConfConfirmed, "RDAP status %q (suffix not delegated)", st)
			}
		}
	}
	if r.Result == "found" && !rdapExpired && !r.Expires.IsZero() {
		left := r.Expires.Sub(now)
		days := int(left.Hours() / 24)
		switch {
		case left < 30*24*time.Hour:
			add(FlagExpiringSoon, SevHigh, ConfConfirmed, "expires %s (in %d days)", r.Expires.Format("2006-01-02"), days)
		case left < 90*24*time.Hour:
			add(FlagExpiring90, SevMedium, ConfConfirmed, "expires %s (in %d days)", r.Expires.Format("2006-01-02"), days)
		case priv && left < 365*24*time.Hour:
			add(FlagShortTerm, SevLow, ConfConfirmed, "expires %s (in %d days); PSL expects >1y", r.Expires.Format("2006-01-02"), days)
		}
	}
	if r.Result == "found" && !r.Created.IsZero() && now.Sub(r.Created) < 365*24*time.Hour {
		sev := SevMedium
		if !priv {
			sev = SevHigh // a suffix registered recently is unusual
		}
		add(FlagNewlyRegistered, sev, ConfConfirmed, "registered %s", r.Created.Format("2006-01-02"))
	}

	// --- DNS-based findings, confidence raised/lowered by RDAP
	rdapHealthy := r.Result == "found" && !rdapExpired && (r.Expires.IsZero() || r.Expires.After(now))
	rdapGone := r.Result == "not_found" || rdapExpired
	switch d.State {
	case DNSDefunct:
		switch {
		case rdapGone:
			add(FlagDefunct, SevCritical, ConfConfirmed, "no NS for %d days (%s), RDAP confirms not registered/expired", d.MissingDays, d.LastStatus)
		case rdapHealthy:
			add(FlagDefunct, SevMedium, ConfHigh, "no NS for %d days (%s) but registration is active: broken/lame delegation", d.MissingDays, d.LastStatus)
		default:
			add(FlagDefunct, SevHigh, ConfMedium, "no NS for %d days (%s); RDAP unavailable, possibly expired", d.MissingDays, d.LastStatus)
		}
	case DNSMissing:
		add(FlagNSMissing, SevLow, ConfLow, "NS missing for %d/%d days (%s)", d.MissingDays, in.Grace, d.LastStatus)
	case DNSChanged:
		sev, conf := SevHigh, ConfMedium
		if len(in.ParkedNS) > 0 || rdapGone {
			sev, conf = SevCritical, ConfHigh
		}
		add(FlagChanged, sev, conf, "NS replaced for %d days: %s -> %s", d.ChangedDays, strings.Join(d.Baseline, ","), strings.Join(d.Current, ","))
	case DNSChanging:
		add(FlagChanging, SevLow, ConfLow, "NS disjoint from baseline for %d/%d days: now %s", d.ChangedDays, in.Grace, strings.Join(d.Current, ","))
	case DNSNoNS:
		if priv && d.NegDays > 0 {
			switch {
			case rdapGone:
				// expired / dropped flags already carry the severity
			case d.NegDays >= in.Grace && rdapHealthy:
				add(FlagNeverResolved, SevMedium, ConfHigh, "no NS on %d check days (%s) but registration is active: broken delegation", d.NegDays, d.LastStatus)
			case d.NegDays >= in.Grace:
				add(FlagNeverResolved, SevHigh, ConfMedium, "no NS on %d check days (%s); RDAP unavailable, possibly expired", d.NegDays, d.LastStatus)
			default:
				add(FlagNeverResolved, SevLow, ConfLow, "no NS on %d/%d check days (%s)", d.NegDays, in.Grace, d.LastStatus)
			}
		}
	case DNSAppeared:
		sev := SevMedium
		if !priv {
			sev = SevHigh
		}
		add(FlagAppeared, sev, ConfMedium, "delegation appeared: %s", strings.Join(d.Current, ","))
	}
	if len(in.ParkedNS) > 0 {
		add(FlagParked, SevHigh, ConfMedium, "parking-like NS: %s", strings.Join(in.ParkedNS, ","))
	}
	if priv && len(in.TXT.Missing) > 0 {
		add(FlagTXTMissing, SevMedium, ConfConfirmed, "%d/%d rule(s) without _psl TXT: %s", len(in.TXT.Missing), in.TXT.Checked, truncList(in.TXT.Missing, 5))
	}
	if d.Inconsistent && d.State == DNSOK {
		add(FlagInconsistent, SevInfo, ConfLow, "resolvers disagreed on last check")
	}
	sort.SliceStable(f, func(i, j int) bool { return f[i].Severity > f[j].Severity })
	return f
}

// MaxSeverity of a flag set.
func MaxSeverity(f []Flag) int {
	m := SevNone
	for _, x := range f {
		if x.Severity > m {
			m = x.Severity
		}
	}
	return m
}

func truncList(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ",")
	}
	return strings.Join(s[:n], ",") + fmt.Sprintf(",... (+%d)", len(s)-n)
}

package checker

import (
	"context"
	"strings"

	"psl-monitor/internal/rdap"
	"psl-monitor/internal/whoisfb"
)

// Fallback is the WHOIS / web-WHOIS fallback client (nil = disabled).
type Fallback interface {
	Lookup(ctx context.Context, domain string) *whoisfb.Domain
}

// needsFallback decides whether an RDAP answer should be complemented by WHOIS:
//   - no RDAP server for the TLD, or RDAP failed -> replace with WHOIS
//   - RDAP found the domain but published no expiry date -> enrich from WHOIS
//
// RDAP "not found" is authoritative and is never second-guessed.
func needsFallback(d *rdap.Domain) bool {
	switch d.Result {
	case rdap.ResultUnsupported, rdap.ResultError:
		return true
	case rdap.ResultFound:
		return d.Expires.IsZero()
	}
	return false
}

// lookupRegistration queries RDAP and, when needed, the WHOIS fallback,
// returning a single merged answer in RDAP form. RDAP always wins where it
// has data; WHOIS fills gaps.
func lookupRegistration(ctx context.Context, rc *rdap.Client, fb Fallback, name string) *rdap.Domain {
	d := rc.Lookup(ctx, name)
	if fb == nil || ctx.Err() != nil || !needsFallback(d) {
		return d
	}
	w := fb.Lookup(ctx, name)
	if ctx.Err() != nil {
		return d
	}
	return mergeFallback(d, w)
}

// mergeFallback combines an RDAP answer with a WHOIS answer.
func mergeFallback(d *rdap.Domain, w *whoisfb.Domain) *rdap.Domain {
	if d.Result == rdap.ResultFound {
		// enrichment only: fill missing fields, keep RDAP as the source of truth
		if w.Result != whoisfb.ResultFound {
			return d
		}
		out := *d
		filled := false
		if out.Expires.IsZero() && !w.Expires.IsZero() {
			out.Expires, filled = w.Expires, true
		}
		if out.Created.IsZero() && !w.Created.IsZero() {
			out.Created, filled = w.Created, true
		}
		if out.Registrar == "" {
			out.Registrar = w.Registrar
		}
		if len(out.Nameservers) == 0 {
			out.Nameservers = w.Nameservers
		}
		if filled {
			out.Source = "rdap+whois"
		}
		return &out
	}

	rdapErr := ""
	if d.Result == rdap.ResultError {
		rdapErr = "rdap: " + d.Err
	}
	out := &rdap.Domain{Source: "whois", Server: whoisServerLabel(w), Elapsed: d.Elapsed + w.Elapsed}
	switch w.Result {
	case whoisfb.ResultFound:
		out.Result = rdap.ResultFound
		out.Created, out.Expires, out.LastChanged = w.Created, w.Expires, w.Updated
		out.Statuses, out.Nameservers, out.Registrar = w.Statuses, w.Nameservers, w.Registrar
	case whoisfb.ResultNotFound:
		out.Result = rdap.ResultNotFound
	case whoisfb.ResultReserved:
		// a registry-reserved label exists as far as monitoring is concerned
		out.Result = rdap.ResultFound
		out.Statuses = []string{"reserved"}
	case whoisfb.ResultUnsupported:
		// neither RDAP nor WHOIS available: keep the RDAP answer
		if d.Result == rdap.ResultUnsupported {
			d.Err = "no RDAP or WHOIS server for TLD"
		}
		return d
	default: // error
		msg := joinErr(rdapErr, "whois: "+w.Err)
		if d.Result == rdap.ResultUnsupported {
			return &rdap.Domain{Result: rdap.ResultError, Source: "whois", Server: whoisServerLabel(w), Err: "whois: " + w.Err}
		}
		d.Err = msg
		return d
	}
	return out
}

func whoisServerLabel(w *whoisfb.Domain) string {
	if w.Server != "" {
		return "whois://" + w.Server
	}
	return "whois (fallback)"
}

func joinErr(a, b string) string {
	return strings.Trim(a+"; "+b, "; ")
}

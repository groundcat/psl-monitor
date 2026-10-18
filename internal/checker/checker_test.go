package checker

import (
	"testing"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/rdap"
	"psl-monitor/internal/store"
)

func TestApplyRDAP(t *testing.T) {
	created := time.Date(2016, 3, 9, 10, 0, 0, 0, time.UTC)
	exp := time.Date(2027, 3, 9, 10, 0, 0, 0, time.UTC)
	tg := &store.Target{}
	evs := applyRDAP(tg, &rdap.Domain{Result: rdap.ResultFound, Created: created, Expires: exp})
	if len(evs) != 0 || !tg.RDAP.EverFound || !tg.RDAP.Created.Equal(created) {
		t.Fatalf("%+v %v", tg.RDAP, evs)
	}
	// same day, different seconds: no re-registration
	evs = applyRDAP(tg, &rdap.Domain{Result: rdap.ResultFound, Created: created.Add(time.Second), Expires: exp})
	if len(evs) != 0 || !tg.RDAP.PrevCreated.IsZero() {
		t.Fatalf("false re-registration: %v", evs)
	}
	// transient error keeps cached data
	applyRDAP(tg, &rdap.Domain{Result: rdap.ResultError, Err: "timeout"})
	if tg.RDAP.Result != rdap.ResultFound || !tg.RDAP.Expires.Equal(exp) || tg.RDAPError != "timeout" {
		t.Fatalf("error overwrote cache: %+v", tg.RDAP)
	}
	// renewal
	evs = applyRDAP(tg, &rdap.Domain{Result: rdap.ResultFound, Created: created, Expires: exp.AddDate(1, 0, 0)})
	if len(evs) != 1 || evs[0][0] != "rdap_expiry_changed" {
		t.Fatalf("%v", evs)
	}
	// dropped
	evs = applyRDAP(tg, &rdap.Domain{Result: rdap.ResultNotFound})
	if len(evs) != 1 || tg.RDAP.Result != rdap.ResultNotFound || !tg.RDAP.EverFound {
		t.Fatalf("%v %+v", evs, tg.RDAP)
	}
	f := analyze.Evaluate(analyze.Input{Section: "private", RDAP: tg.RDAP, DNS: analyze.NSState{State: analyze.DNSOK}, Now: time.Now()})
	if analyze.MaxSeverity(f) != analyze.SevCritical {
		t.Fatalf("%+v", f)
	}
	// re-registered by someone else
	evs = applyRDAP(tg, &rdap.Domain{Result: rdap.ResultFound, Created: time.Now().Add(-48 * time.Hour), Expires: time.Now().AddDate(1, 0, 0)})
	if len(evs) != 3 || tg.RDAP.PrevCreated.IsZero() {
		t.Fatalf("%v", evs)
	}
	f = analyze.Evaluate(analyze.Input{Section: "private", RDAP: tg.RDAP, DNS: analyze.NSState{State: analyze.DNSOK}, Now: time.Now()})
	if f[0].Type != analyze.FlagReRegistered {
		t.Fatalf("%+v", f)
	}
}

func TestNewFlags(t *testing.T) {
	if newFlags(",a,b,", ",a,") || !newFlags(",a,", ",a,b,") || newFlags(",a,", ",a,inconsistent,") {
		t.Fatal("newFlags")
	}
}

func TestApplyRDAPSource(t *testing.T) {
	tg := &store.Target{}
	applyRDAP(tg, &rdap.Domain{Result: rdap.ResultFound, Source: "whois", Server: "whois://whois.nic.it", Expires: time.Now().AddDate(1, 0, 0)})
	if tg.RDAPSource != "whois" || tg.RDAPServer != "whois://whois.nic.it" {
		t.Fatalf("%+v", tg)
	}
	applyRDAP(tg, &rdap.Domain{Result: rdap.ResultUnsupported, Err: "no RDAP or WHOIS server for TLD"})
	if tg.RDAP.Result != rdap.ResultFound || tg.RDAPError != "no RDAP or WHOIS server for TLD" {
		t.Fatalf("unsupported must not clobber cached result: %+v", tg.RDAP)
	}
}

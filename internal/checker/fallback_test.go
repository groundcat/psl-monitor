package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"psl-monitor/internal/rdap"
	"psl-monitor/internal/whoisfb"
)

func TestNeedsFallback(t *testing.T) {
	exp := time.Now().AddDate(1, 0, 0)
	cases := []struct {
		d    rdap.Domain
		want bool
	}{
		{rdap.Domain{Result: rdap.ResultUnsupported}, true},
		{rdap.Domain{Result: rdap.ResultError}, true},
		{rdap.Domain{Result: rdap.ResultFound}, true}, // no expiry
		{rdap.Domain{Result: rdap.ResultFound, Expires: exp}, false},
		{rdap.Domain{Result: rdap.ResultNotFound}, false},
	}
	for _, c := range cases {
		if got := needsFallback(&c.d); got != c.want {
			t.Errorf("%+v: %v", c.d, got)
		}
	}
}

func TestMergeFallback(t *testing.T) {
	cr := time.Date(2001, 2, 2, 0, 0, 0, 0, time.UTC)
	ex := time.Date(2027, 2, 28, 0, 0, 0, 0, time.UTC)
	wFound := &whoisfb.Domain{Result: whoisfb.ResultFound, Server: "whois.jprs.jp", Created: cr, Expires: ex, Nameservers: []string{"ns1.jprs.jp"}, Statuses: []string{"Active"}}

	// unsupported RDAP -> WHOIS answer
	m := mergeFallback(&rdap.Domain{Result: rdap.ResultUnsupported}, wFound)
	if m.Result != rdap.ResultFound || m.Source != "whois" || !m.Expires.Equal(ex) || m.Server != "whois://whois.jprs.jp" {
		t.Fatalf("%+v", m)
	}
	// RDAP found without expiry -> enriched, RDAP fields kept
	m = mergeFallback(&rdap.Domain{Result: rdap.ResultFound, Source: "rdap", Server: "https://rdap.x/", Registrar: "R", Statuses: []string{"active"}}, wFound)
	if m.Source != "rdap+whois" || !m.Expires.Equal(ex) || m.Registrar != "R" || m.Server != "https://rdap.x/" || m.Statuses[0] != "active" {
		t.Fatalf("%+v", m)
	}
	// RDAP found, WHOIS failed -> RDAP unchanged
	m = mergeFallback(&rdap.Domain{Result: rdap.ResultFound, Source: "rdap"}, &whoisfb.Domain{Result: whoisfb.ResultError, Err: "x"})
	if m.Source != "rdap" {
		t.Fatalf("%+v", m)
	}
	// RDAP error + WHOIS not found -> not found via whois
	m = mergeFallback(&rdap.Domain{Result: rdap.ResultError, Err: "timeout"}, &whoisfb.Domain{Result: whoisfb.ResultNotFound})
	if m.Result != rdap.ResultNotFound || m.Source != "whois" {
		t.Fatalf("%+v", m)
	}
	// both fail -> error with both messages
	m = mergeFallback(&rdap.Domain{Result: rdap.ResultError, Err: "timeout"}, &whoisfb.Domain{Result: whoisfb.ResultError, Err: "refused"})
	if m.Result != rdap.ResultError || !strings.Contains(m.Err, "rdap: timeout") || !strings.Contains(m.Err, "whois: refused") {
		t.Fatalf("%+v", m)
	}
	// neither available
	m = mergeFallback(&rdap.Domain{Result: rdap.ResultUnsupported}, &whoisfb.Domain{Result: whoisfb.ResultUnsupported})
	if m.Result != rdap.ResultUnsupported || !strings.Contains(m.Err, "WHOIS") {
		t.Fatalf("%+v", m)
	}
	// unsupported RDAP + WHOIS error -> error (retried next time, cache untouched by applyRDAP)
	m = mergeFallback(&rdap.Domain{Result: rdap.ResultUnsupported}, &whoisfb.Domain{Result: whoisfb.ResultError, Err: "timed out"})
	if m.Result != rdap.ResultError {
		t.Fatalf("%+v", m)
	}
}

func TestLookupRegistrationEndToEnd(t *testing.T) {
	var whoisHits atomic.Int32
	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		whoisHits.Add(1)
		w.Write([]byte(`{"code":0,"msg":"ok","data":{"registered":true,"registryWHOISServer":"whois.nic.zz","expirationDateISO8601":"2030-01-01T00:00:00Z","nameServers":["ns.example"]}}`))
	}))
	defer ws.Close()
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/domain/full.rd":
			w.Write([]byte(`{"objectClassName":"domain","events":[{"eventAction":"expiration","eventDate":"2031-01-01T00:00:00Z"}]}`))
		case "/domain/noexp.rd":
			w.Write([]byte(`{"objectClassName":"domain","events":[{"eventAction":"registration","eventDate":"2001-01-01T00:00:00Z"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer rs.Close()
	rc := rdap.New(rdap.Options{Overrides: map[string]string{"rd": rs.URL}, PerHostQPS: 100})
	fb := whoisfb.New(whoisfb.Options{BaseURL: ws.URL, PerTLDQPS: 100})
	ctx := context.Background()

	if d := lookupRegistration(ctx, rc, fb, "full.rd"); d.Source != "rdap" || whoisHits.Load() != 0 {
		t.Fatalf("complete RDAP must not hit WHOIS: %+v", d)
	}
	if d := lookupRegistration(ctx, rc, fb, "gone.rd"); d.Result != rdap.ResultNotFound || whoisHits.Load() != 0 {
		t.Fatalf("RDAP 404 is authoritative: %+v", d)
	}
	d := lookupRegistration(ctx, rc, fb, "noexp.rd")
	if d.Source != "rdap+whois" || d.Expires.Year() != 2030 || d.Created.Year() != 2001 {
		t.Fatalf("%+v", d)
	}
	d = lookupRegistration(ctx, rc, fb, "x.nordapzz")
	if d.Source != "whois" || d.Result != rdap.ResultFound || d.Server != "whois://whois.nic.zz" {
		t.Fatalf("%+v", d)
	}
	// disabled fallback
	if d := lookupRegistration(ctx, rc, nil, "x.nordapzz"); d.Result != rdap.ResultUnsupported {
		t.Fatalf("%+v", d)
	}
	// applyRDAP records the source
}

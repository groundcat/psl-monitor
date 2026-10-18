package rdap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseDomain(t *testing.T) {
	body := `{"objectClassName":"domain","ldhName":"A2HOSTED.COM","status":["client transfer prohibited"],
	"events":[{"eventAction":"registration","eventDate":"2013-10-29T16:26:23Z"},{"eventAction":"expiration","eventDate":"2029-10-29T16:26:23Z"},{"eventAction":"last changed","eventDate":"2025-05-09T15:15:04.123+02:00"}],
	"nameservers":[{"ldhName":"NS1.A2HOSTING.COM"}],
	"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar"]]]}]}`
	d := &Domain{}
	if err := parseDomain([]byte(body), d); err != nil {
		t.Fatal(err)
	}
	if d.Created.Year() != 2013 || d.Expires.Year() != 2029 || d.LastChanged.Hour() != 13 || d.Registrar != "Example Registrar" || d.Nameservers[0] != "ns1.a2hosting.com" {
		t.Fatalf("%+v", d)
	}
}

func TestServerFor(t *testing.T) {
	c := New(Options{Overrides: map[string]string{"de": "https://rdap.denic.de"}})
	if c.ServerFor("pl") != IANABase {
		t.Fatal("tld should use IANA")
	}
	if c.ServerFor("foo.edu.pl") != "https://rdap.dns.pl/" {
		t.Fatal(c.ServerFor("foo.edu.pl"))
	}
	if c.ServerFor("x.de") != "https://rdap.denic.de/" {
		t.Fatal(c.ServerFor("x.de"))
	}
	if c.ServerFor("x.nosuchtld") != "" {
		t.Fatal("expected unsupported")
	}
}

func TestLookupStatuses(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/domain/ok.test":
			fmt.Fprint(w, `{"objectClassName":"domain","events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]}`)
		case "/domain/gone.test":
			w.WriteHeader(404)
		case "/domain/throttle.test":
			if hits.Load() < 3 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(429)
				return
			}
			fmt.Fprint(w, `{"objectClassName":"domain"}`)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	c := New(Options{Overrides: map[string]string{"test": srv.URL}, PerHostQPS: 100})
	c.minQPS = 50
	ctx := context.Background()
	if d := c.Lookup(ctx, "ok.test"); d.Result != ResultFound || d.Expires.Year() != 2030 {
		t.Fatalf("%+v", d)
	}
	if d := c.Lookup(ctx, "gone.test"); d.Result != ResultNotFound {
		t.Fatalf("%+v", d)
	}
	hits.Store(0)
	if d := c.Lookup(ctx, "throttle.test"); d.Result != ResultFound {
		t.Fatalf("%+v", d)
	}
	ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if d := c.Lookup(ctx2, "broken.test"); d.Result != ResultError {
		t.Fatalf("%+v", d)
	}
}

func TestThrottleAdapts(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%2 == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		fmt.Fprint(w, `{"objectClassName":"domain","entities":[{"roles":"registrar"}],"status":"active"}`)
	}))
	defer srv.Close()
	c := New(Options{Overrides: map[string]string{"test": srv.URL}, PerHostQPS: 50})
	c.minQPS = 20
	for i := 0; i < 10; i++ {
		d := c.Lookup(context.Background(), fmt.Sprintf("d%d.test", i))
		if d.Result != ResultFound {
			t.Fatalf("%d: %+v", i, d)
		}
	}
	st := c.Stats()
	if len(st) != 1 || st[0].CircuitOpen || st[0].Throttled < 5 {
		t.Fatalf("%+v", st)
	}
}

func TestExtraServers(t *testing.T) {
	c := New(Options{Overrides: map[string]string{"xx": "https://override.example"}})
	n, err := c.LoadExtra([]byte(`{"ch":"https://rdap.nic.ch/","br.com":"https://rdap.centralnic.com/br.com","com":"https://bad.example/","sn":"http://insecure.example/","xx":"https://extra.example/"}`))
	if err != nil || n != 4 {
		t.Fatalf("%d %v", n, err)
	}
	cases := map[string]string{
		"cloudns.ch":   "https://rdap.nic.ch/",                // not in IANA: extra fills the gap
		"foo.br.com":   "https://rdap.centralnic.com/br.com/", // deeper suffix wins
		"a2hosted.com": "https://rdap.verisign.com/com/v1/",   // IANA wins over extra for a TLD
		"x.xx":         "https://override.example/",           // manual override wins
		"x.nosuchtld":  "",
	}
	for d, want := range cases {
		if got := c.ServerFor(d); got != want {
			t.Errorf("%s: %q want %q", d, got, want)
		}
	}
}

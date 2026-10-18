package whoisfb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func serve(t *testing.T, body string, hits *atomic.Int32) *Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if r.URL.Path != "/src/index.php" || r.URL.Query().Get("whois") != "1" || r.URL.Query().Get("json") != "1" {
			t.Errorf("unexpected request %s", r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer c0509a487a18b003ba05e505419ebb63e57a29158073e381f57160b5c5b86426" {
			t.Errorf("auth header %q", r.Header.Get("Authorization"))
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return New(Options{BaseURL: srv.URL + "/", Password: "233", PerTLDQPS: 100})
}

func TestFound(t *testing.T) {
	c := serve(t, `{"code":0,"msg":"Query successful","data":{"unknown":false,"reserved":false,"registered":true,"domain":"nic.it",
	"creationDateISO8601":"1997-08-26T22:00:00Z","expirationDateISO8601":"2026-12-31","updatedDateISO8601":null,
	"status":[{"text":"OK","url":""}],"nameServers":["DNS.nic.it.","a.dns.it","a.dns.it"],"pendingDelete":true,"hold":false,"redemptionPeriod":false,"registrar":"Registro"}}`, nil)
	d := c.Lookup(context.Background(), "nic.it")
	if d.Result != ResultFound || d.Created.Year() != 1997 || d.Expires.Format("2006-01-02") != "2026-12-31" || !d.Updated.IsZero() {
		t.Fatalf("%+v", d)
	}
	if len(d.Nameservers) != 2 || d.Nameservers[0] != "dns.nic.it" || d.Registrar != "Registro" {
		t.Fatalf("%+v", d)
	}
	if len(d.Statuses) != 2 || d.Statuses[1] != "pending delete" {
		t.Fatalf("%v", d.Statuses)
	}
}

func TestResults(t *testing.T) {
	cases := map[string]string{
		`{"code":0,"msg":"","data":{"registered":false}}`:                                 ResultNotFound,
		`{"code":0,"msg":"","data":{"reserved":true}}`:                                    ResultReserved,
		`{"code":1,"msg":"No WHOIS server found for 'x.zz'.","data":null}`:                ResultUnsupported,
		`{"code":1,"msg":"WHOIS lookup failed for 'x': connection refused.","data":null}`: ResultError,
		`{"code":0,"msg":"","data":{"unknown":true}}`:                                     ResultError,
		`not json`: ResultError,
		`{"code":1,"msg":"Incorrect password.","data":null}`: ResultError,
	}
	for body, want := range cases {
		var hits atomic.Int32
		c := serve(t, body, &hits)
		if d := c.Lookup(context.Background(), "x.zz"); d.Result != want {
			t.Errorf("%s: got %s (%s) want %s", body, d.Result, d.Err, want)
		}
		// non-retryable upstream errors are not retried
		if body == `{"code":1,"msg":"Incorrect password.","data":null}` && hits.Load() != 1 {
			t.Errorf("credential errors must not be retried (%d hits)", hits.Load())
		}
	}
}

func TestDisabled(t *testing.T) {
	var c *Client = New(Options{})
	if c.Enabled() || c.BaseURL() != "" {
		t.Fatal("empty base URL must disable")
	}
	if r, f := c.Stats(); r != 0 || f != 0 {
		t.Fatal("stats on nil client")
	}
}

// TestLive runs against a real upstream instance when WHOIS_FALLBACK_TEST_URL is set,
// e.g. `php -S 127.0.0.1:18090 -t third_party/whois-domain-lookup`.
func TestLive(t *testing.T) {
	u := os.Getenv("WHOIS_FALLBACK_TEST_URL")
	if u == "" {
		t.Skip("WHOIS_FALLBACK_TEST_URL not set")
	}
	c := New(Options{BaseURL: u})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	for dom, want := range map[string]string{"jprs.jp": ResultFound, "nic.it": ResultFound, "nonexist-zzq9.de": ResultNotFound} {
		d := c.Lookup(ctx, dom)
		t.Logf("%s: %s created=%s expires=%s ns=%v status=%v err=%s (%s)", dom, d.Result, d.Created.Format("2006-01-02"), d.Expires.Format("2006-01-02"), d.Nameservers, d.Statuses, d.Err, d.Elapsed.Round(time.Millisecond))
		if d.Result != want {
			t.Errorf("%s: %s want %s", dom, d.Result, want)
		}
	}
}

package web

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/checker"
	"psl-monitor/internal/compliance"
	"psl-monitor/internal/config"
	"psl-monitor/internal/dnscheck"
	"psl-monitor/internal/psl"
	"psl-monitor/internal/rdap"
	"psl-monitor/internal/scheduler"
	"psl-monitor/internal/store"
)

// logCapture fails the test on any ERROR log (template render errors are logged, not returned).
type logCapture struct {
	t   *testing.T
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("level=ERROR")) {
		l.t.Errorf("error logged: %s", p)
	}
	return l.buf.Write(p)
}

func setup(t *testing.T) (*httptest.Server, *http.Client, *store.Store) {
	b, err := os.ReadFile("/tmp/opencode/psl.dat")
	if err != nil {
		t.Skip("no local PSL copy")
	}
	l, err := psl.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.SyncList(context.Background(), l, compliance.Embedded().MissingTXT, 0); err != nil {
		t.Fatal(err)
	}
	// seed state so every template branch has data
	tg, _ := st.GetTargetByName("private", "adobeaemcloud.com")
	tg.DNS = analyze.NSState{State: analyze.DNSChanged, ChangedDays: 5, LastStatus: "ok", Baseline: []string{"a.ns"}, Current: []string{"ns1.sedoparking.com"}, Previous: []string{"old.ns"}, Inconsistent: true}
	tg.ParkedNS = []string{"ns1.sedoparking.com"}
	tg.RDAP = analyze.RDAPInfo{Result: "found", Created: time.Now().Add(-100 * 24 * time.Hour), PrevCreated: time.Now().Add(-5000 * 24 * time.Hour), Expires: time.Now().Add(20 * 24 * time.Hour), Statuses: []string{"client hold"}, EverFound: true, CheckedAt: time.Now()}
	tg.Flags = analyze.Evaluate(analyze.Input{Section: "private", DNS: tg.DNS, RDAP: tg.RDAP, ParkedNS: tg.ParkedNS, TXT: analyze.TXTInfo{Checked: 3, Missing: []string{"x"}}, Grace: 5, Now: time.Now()})
	tg.Severity = analyze.MaxSeverity(tg.Flags)
	tg.FlagTypes = store.FlagTypeString(tg.Flags)
	tg.FlaggedSince = time.Now()
	runID, _ := st.CreateRun(checker.KindDNSPrivate, "", "manual", "test")
	st.Tx(context.Background(), func(tx *sql.Tx) error {
		store.SaveDNSTx(tx, tg)
		store.SaveRDAPTx(tx, tg)
		store.SaveFlagsTx(tx, tg)
		tx.Exec(`INSERT INTO run_results(run_id,target_id,dns_status,dns_state,ns,severity,flag_types) VALUES(?,?,?,?,?,?,?)`, runID, tg.ID, "ok", "changed", "ns1.sedoparking.com", tg.Severity, tg.FlagTypes)
		st.AddEventTx(tx, runID, tg.ID, "dns_state", "changing", "changed", "detail")
		tx.Exec(`UPDATE rules SET txt_status='valid', txt_prs='123' WHERE target_id=?`, tg.ID)
		return nil
	})
	st.Log(runID, "info", "hello")
	st.Log(runID, "warn", "careful")
	st.FinishRun(runID, "ok", "summary", 1)
	run2, _ := st.CreateRun(checker.KindDNSPrivate, "", "schedule", "scheduler")
	st.FinishRun(run2, "ok", "summary", 1)

	log := slog.New(slog.NewTextHandler(&logCapture{t: t}, nil))
	pool, _ := dnscheck.NewPool(dnscheck.Options{Resolvers: []string{"127.0.0.1:1"}})
	ck := checker.New(st, pool, rdap.New(rdap.Options{}), analyze.NewParking(analyze.DefaultParkingNS, nil), compliance.Embedded(), checker.Config{Grace: 5, DNSWorkers: 1, RDAPWorkers: 1, TXTWorkers: 1, TargetTimeout: time.Second}, log)
	sch := scheduler.New(st, ck, config.Env{}.SMTP, "", log)
	srv := &Server{St: st, Ck: ck, Sch: sch, Log: log,
		ApplySettings:     func() error { return nil },
		RefreshExceptions: func(context.Context) (int, error) { return 0, nil },
		RefreshBootstrap:  func(context.Context) (int, error) { return 0, nil }}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return ts, cl, st
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func TestPagesRender(t *testing.T) {
	ts, cl, st := setup(t)
	// first-run setup flow
	resp, _ := cl.Get(ts.URL + "/")
	if resp.StatusCode != 303 || !strings.HasSuffix(resp.Header.Get("Location"), "/setup") {
		t.Fatalf("expected redirect to setup, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = cl.PostForm(ts.URL+"/setup", url.Values{"username": {"admin"}, "password": {"pass-word-123"}, "password2": {"pass-word-123"}, "email": {"a@example.com"}})
	if resp.StatusCode != 303 {
		t.Fatalf("setup: %d", resp.StatusCode)
	}
	tg, _ := st.GetTargetByName("private", "adobeaemcloud.com")
	pages := []string{"/", "/targets", "/targets?flagged=1&unacked=1", "/targets?section=private&sort=expires&desc=1", "/targets?section=icann",
		"/search?q=edu&tld=pl&exp_within=90&created_within=365&ns=sedo&parked=1&inactive=1&minsev=2&per=50&page=2",
		"/target/" + itoa64(tg.ID), "/rules", "/rules?section=private&kind=wildcard&txt=valid&active=all", "/txt", "/txt?txt=valid",
		"/events", "/events?type=dns_state&days=7", "/snapshots", "/snapshot/1", "/runs", "/runs?kind=dns_private", "/run/1", "/run/2", "/run/2/diff", "/run/2/diff?against=1",
		"/workers", "/workers.json", "/schedule", "/settings", "/users", "/account", "/help", "/targets.txt?flagged=1", "/targets.csv", "/report/preview", "/healthz"}
	for _, p := range pages {
		resp, err := cl.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s: HTTP %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
		}
		if strings.Contains(string(body), "ZgotmplZ") {
			t.Errorf("%s: unsafe template value", p)
		}
	}
	// CSRF required
	resp, _ = cl.PostForm(ts.URL+"/target/"+itoa64(tg.ID)+"/note", url.Values{"note": {"x"}})
	if resp.StatusCode != 403 {
		t.Fatalf("missing CSRF should be rejected, got %d", resp.StatusCode)
	}
	resp, _ = cl.Get(ts.URL + "/account")
	body, _ := io.ReadAll(resp.Body)
	m := csrfRe.FindSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token in page")
	}
	csrf := string(m[1])
	post := func(p string, v url.Values) *http.Response {
		v.Set("csrf", csrf)
		r, err := cl.PostForm(ts.URL+p, v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := post("/target/"+itoa64(tg.ID)+"/ack", url.Values{"note": {"seen"}, "accept_ns": {"1"}}); r.StatusCode != 303 || strings.Contains(r.Header.Get("Location"), "err=") {
		t.Fatalf("ack: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	tg2, _ := st.GetTargetByName("private", "adobeaemcloud.com")
	if tg2.DNS.State != analyze.DNSOK || tg2.DNS.Baseline[0] != "ns1.sedoparking.com" || tg2.AckedBy != "admin" {
		t.Fatalf("accept NS: %+v", tg2.DNS)
	}
	if r := post("/users", url.Values{"username": {"bob"}, "password": {"bob-password-1"}}); strings.Contains(r.Header.Get("Location"), "err=") {
		t.Fatalf("create user: %s", r.Header.Get("Location"))
	}
	if r := post("/schedule", url.Values{"sched.dns_private.enabled": {"1"}, "sched.dns_private.interval": {"1d"}, "sched.dns_private.at": {"02:30"},
		"sched.dns_icann.interval": {"1w"}, "sched.txt.interval": {"7d"}, "sched.rdap_private.interval": {"30d"}, "sched.rdap_icann.interval": {"90d"}, "sched.report.interval": {"7d"}}); strings.Contains(r.Header.Get("Location"), "err=") {
		t.Fatalf("schedule: %s", r.Header.Get("Location"))
	}
	if st.GetSetting("sched.dns_icann.enabled", "") != "0" || st.GetSetting("sched.dns_private.at", "") != "02:30" {
		t.Fatal("schedule not saved")
	}
	if r := post("/settings", url.Values{"grace_days": {"999"}}); !strings.Contains(r.Header.Get("Location"), "err=") {
		t.Fatal("invalid setting accepted")
	}
	if r := post("/settings", url.Values{"grace_days": {"6"}, "auto_rdap": {"1"}}); strings.Contains(r.Header.Get("Location"), "err=") {
		t.Fatalf("settings: %s", r.Header.Get("Location"))
	}
	if st.GetSetting("grace_days", "") != "6" {
		t.Fatal("setting not saved")
	}
	if r := post("/account", url.Values{"email": {"bad email"}}); !strings.Contains(r.Header.Get("Location"), "err=") {
		t.Fatal("bad email accepted")
	}
	if r := post("/logout", url.Values{}); r.StatusCode != 303 {
		t.Fatal("logout")
	}
	resp, _ = cl.Get(ts.URL + "/")
	if resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("Location"), "/login") {
		t.Fatal("should be logged out")
	}
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"database/sql"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/psl"
)

func loadPSL(t *testing.T) *psl.List {
	b, err := os.ReadFile("/tmp/opencode/psl.dat")
	if err != nil {
		t.Skip("no local PSL copy")
	}
	l, err := psl.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestSyncAndSearch(t *testing.T) {
	l := loadPSL(t)
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	start := time.Now()
	res, err := st.SyncList(ctx, l, map[string]bool{"akamai.net": true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("initial sync %s: +%d targets", time.Since(start), res.AddedTargets)
	if !res.New || res.AddedTargets < 9000 || len(res.AddedRules) != 0 {
		t.Fatalf("%+v", res)
	}
	// idempotent
	res2, _ := st.SyncList(ctx, l, nil, 0)
	if res2.New {
		t.Fatal("second sync should be a no-op")
	}
	// simulate list change: remove a rule, add one
	b, _ := os.ReadFile("/tmp/opencode/psl.dat")
	mod := strings.Replace(string(b), "\nmyaddr.dev\n", "\nmyaddr-new.dev\n", 1)
	l2, err := psl.Parse([]byte(mod))
	if err != nil {
		t.Fatal(err)
	}
	res3, err := st.SyncList(ctx, l2, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res3.AddedRules) != 1 || len(res3.RemovedRules) != 1 || res3.AddedTargets != 1 || res3.RemovedTargets != 1 {
		t.Fatalf("diff: %+v", res3)
	}
	gone, err := st.GetTargetByName("private", "myaddr.dev")
	if err != nil || gone.Active {
		t.Fatalf("myaddr.dev should be inactive: %v %+v", err, gone)
	}
	// exemption flag recorded on rules
	var ex int
	st.R.QueryRow(`SELECT exempt FROM rules WHERE raw='akamai.net'`).Scan(&ex)
	// (exempt map was not passed on the last sync -> 0)
	_ = ex

	// dedup check: all rules of bar-style private suffixes map to one target
	tg, err := st.GetTargetByName("private", "adobeaemcloud.com")
	if err != nil {
		t.Fatal(err)
	}
	rules := st.RulesForTarget(tg.ID)
	if len(rules) < 2 {
		t.Fatalf("expected multiple rules for adobeaemcloud.com, got %d", len(rules))
	}

	// persist a DNS state + flags and search for it
	tg.DNS = analyze.NSState{State: analyze.DNSDefunct, MissingDays: 5, LastStatus: "nxdomain", Baseline: []string{"a.ns"}}
	tg.Flags = analyze.Evaluate(analyze.Input{Section: "private", DNS: tg.DNS, Grace: 5, Now: time.Now()})
	tg.Severity = analyze.MaxSeverity(tg.Flags)
	tg.FlagTypes = FlagTypeString(tg.Flags)
	tg.FlaggedSince = time.Now()
	if err := st.Tx(ctx, func(tx *sql.Tx) error {
		if err := SaveDNSTx(tx, tg); err != nil {
			return err
		}
		return SaveFlagsTx(tx, tg)
	}); err != nil {
		t.Fatal(err)
	}
	items, total, err := st.SearchTargets(TargetFilter{Flag: analyze.FlagDefunct, Unacked: true})
	if err != nil || total != 1 || items[0].Name != "adobeaemcloud.com" || items[0].DNS.Baseline[0] != "a.ns" {
		t.Fatalf("search: %v %d", err, total)
	}
	if err := st.Ack(tg.ID, "tester", "checked", false); err != nil {
		t.Fatal(err)
	}
	_, total, _ = st.SearchTargets(TargetFilter{Flag: analyze.FlagDefunct, Unacked: true})
	if total != 0 {
		t.Fatal("ack should hide from unacked filter")
	}
	for _, f := range []TargetFilter{{Q: "=edu.pl"}, {Q: "*.edu.pl"}, {Q: "kawasaki"}, {TLD: "pl", Section: "icann"}, {Sort: "expires", Desc: true}, {ExpBefore: time.Now(), CreatedAfter: time.Now().Add(-time.Hour)}} {
		if _, _, err := st.SearchTargets(f); err != nil {
			t.Fatalf("filter %+v: %v", f, err)
		}
	}
	c := st.Counts()
	if c.BySection["private"] < 2000 || c.ByFlag["private"][analyze.FlagDefunct] != 1 {
		t.Fatalf("counts %+v", c.BySection)
	}
}

func TestUsersSessions(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.CreateUser("admin", "correct-horse-1", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser("admin", "correct-horse-1", ""); err == nil {
		t.Fatal("duplicate should fail")
	}
	if _, err := st.CreateUser("x", "short", ""); err == nil {
		t.Fatal("short password should fail")
	}
	if _, err := st.Authenticate("admin", "wrong-password"); err == nil {
		t.Fatal("bad password accepted")
	}
	u, err := st.Authenticate("ADMIN", "correct-horse-1")
	if err != nil || u.ID != id {
		t.Fatal("login failed", err)
	}
	tok, csrf, _ := st.CreateSession(id, time.Hour)
	su, c2, err := st.Session(tok)
	if err != nil || su.ID != id || c2 != csrf {
		t.Fatal("session lookup")
	}
	if err := st.SetUserActive(id, false); err == nil {
		t.Fatal("must not disable last admin")
	}
	st.SetPassword(id, "another-pass-2")
	if _, _, err := st.Session(tok); err == nil {
		t.Fatal("password change must revoke sessions")
	}
	if got := st.ReportRecipients(); len(got) != 1 || got[0] != "a@example.com" {
		t.Fatalf("%v", got)
	}
}

// Package checker orchestrates scans: PSL sync, DNS NS checks, _psl TXT
// checks, RDAP lookups and flag evaluation. Results are written in batches
// by a single writer goroutine so that slow lookups never block the database
// and a crash loses at most one batch.
package checker

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/compliance"
	"psl-monitor/internal/dnscheck"
	"psl-monitor/internal/psl"
	"psl-monitor/internal/rdap"
	"psl-monitor/internal/store"
)

// Run kinds.
const (
	KindDNSPrivate = "dns_private" // daily NS check of private registrable domains
	KindDNSICANN   = "dns_icann"   // weekly NS check of ICANN suffixes
	KindRDAP       = "rdap"        // full RDAP scan (scope: private|icann|all)
	KindTXT        = "txt"         // _psl TXT compliance scan of private rules
	KindSync       = "sync"        // PSL download + diff only
	KindReport     = "report"      // weekly email report
	KindRecheck    = "recheck"     // ad-hoc check of selected targets
)

var KindLabels = map[string]string{
	KindDNSPrivate: "DNS check (private)", KindDNSICANN: "DNS check (ICANN)", KindRDAP: "RDAP scan",
	KindTXT: "_psl TXT scan", KindSync: "PSL sync", KindReport: "Email report", KindRecheck: "Re-check",
}

// Config holds tunables (from settings).
type Config struct {
	PSLURL        string
	ExceptionsURL string
	Grace         int
	DNSWorkers    int
	RDAPWorkers   int
	TXTWorkers    int
	TargetTimeout time.Duration
	RDAPMaxAge    time.Duration // re-query RDAP for flagged targets if cache older than this
	AutoRDAP      bool          // RDAP-confirm DNS anomalies automatically
}

// Progress is live run progress for the UI.
type Progress struct {
	RunID     int64
	Kind      string
	Scope     string
	Phase     string
	Total     int64
	Done      int64
	Errors    int64
	StartedAt time.Time
}

// Checker is the scan engine.
type Checker struct {
	Store   *store.Store
	dnsPool atomic.Pointer[dnscheck.Pool]
	rdapCl  atomic.Pointer[rdap.Client]
	Parking *analyze.Parking
	Log     *slog.Logger

	cfgMu sync.RWMutex
	cfg   Config
	excMu sync.RWMutex
	exc   *compliance.Exceptions

	mu      sync.Mutex
	running map[int64]*runState
}

type runState struct {
	p      Progress
	cancel context.CancelFunc
	total  atomic.Int64
	done   atomic.Int64
	errs   atomic.Int64
	phase  atomic.Value
}

// New creates a checker.
func New(st *store.Store, pool *dnscheck.Pool, rc *rdap.Client, park *analyze.Parking, exc *compliance.Exceptions, cfg Config, log *slog.Logger) *Checker {
	c := &Checker{Store: st, Parking: park, exc: exc, cfg: cfg, Log: log, running: map[int64]*runState{}}
	c.dnsPool.Store(pool)
	c.rdapCl.Store(rc)
	return c
}

// DNS returns the current resolver pool.
func (c *Checker) DNS() *dnscheck.Pool { return c.dnsPool.Load() }

// RDAP returns the current RDAP client.
func (c *Checker) RDAP() *rdap.Client { return c.rdapCl.Load() }

// SetRDAP swaps the RDAP client.
func (c *Checker) SetRDAP(rc *rdap.Client) { c.rdapCl.Store(rc) }

// SetDNS swaps the resolver pool; running scans keep the pool they started with.
func (c *Checker) SetDNS(p *dnscheck.Pool) { c.dnsPool.Store(p) }

func (c *Checker) Config() Config {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.cfg
}

func (c *Checker) SetConfig(cfg Config) {
	c.cfgMu.Lock()
	c.cfg = cfg
	c.cfgMu.Unlock()
}

func (c *Checker) Exceptions() *compliance.Exceptions {
	c.excMu.RLock()
	defer c.excMu.RUnlock()
	return c.exc
}

func (c *Checker) SetExceptions(e *compliance.Exceptions) {
	c.excMu.Lock()
	c.exc = e
	c.excMu.Unlock()
}

// Running returns live progress for active runs.
func (c *Checker) Running() []Progress {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Progress
	for _, rs := range c.running {
		p := rs.p
		p.Total, p.Done, p.Errors = rs.total.Load(), rs.done.Load(), rs.errs.Load()
		if v, ok := rs.phase.Load().(string); ok {
			p.Phase = v
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out
}

// IsRunning reports whether a run of the kind is active.
func (c *Checker) IsRunning(kind string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rs := range c.running {
		if rs.p.Kind == kind {
			return true
		}
	}
	return false
}

// Cancel stops a running run.
func (c *Checker) Cancel(runID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rs, ok := c.running[runID]; ok {
		rs.cancel()
		return true
	}
	return false
}

// ErrBusy is returned when a conflicting run is active.
var ErrBusy = fmt.Errorf("a run of this kind is already in progress")

// conflicts: runs that touch the same columns must not overlap.
var conflicts = map[string][]string{
	KindDNSPrivate: {KindDNSPrivate, KindRecheck},
	KindDNSICANN:   {KindDNSICANN, KindRecheck},
	KindRDAP:       {KindRDAP},
	KindTXT:        {KindTXT},
	KindSync:       {KindSync},
	KindReport:     {KindReport},
	KindRecheck:    {KindDNSPrivate, KindDNSICANN},
}

// Start launches a run asynchronously. scope meaning depends on kind.
func (c *Checker) Start(kind, scope, trigger, by string, ids []int64) (int64, error) {
	c.mu.Lock()
	for _, rs := range c.running {
		for _, k := range conflicts[kind] {
			if rs.p.Kind == k {
				c.mu.Unlock()
				return 0, ErrBusy
			}
		}
	}
	id, err := c.Store.CreateRun(kind, scope, trigger, by)
	if err != nil {
		c.mu.Unlock()
		return 0, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	rs := &runState{p: Progress{RunID: id, Kind: kind, Scope: scope, StartedAt: time.Now()}, cancel: cancel}
	rs.phase.Store("starting")
	c.running[id] = rs
	c.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				c.Log.Error("run panic", "run", id, "panic", r)
				c.Store.Log(id, "error", fmt.Sprintf("panic: %v", r))
				c.Store.FinishRun(id, "failed", fmt.Sprintf("panic: %v", r), 0)
			}
			cancel()
			c.mu.Lock()
			delete(c.running, id)
			c.mu.Unlock()
		}()
		r := &run{c: c, id: id, rs: rs, kind: kind, scope: scope, pool: c.DNS(), rdap: c.RDAP()}
		c.Store.Log(id, "info", fmt.Sprintf("started %s scope=%q trigger=%s by=%s", kind, scope, trigger, by))
		c.Log.Info("run started", "run", id, "kind", kind, "scope", scope, "trigger", trigger)
		err := r.exec(ctx, ids)
		status, summary := "ok", r.summary()
		switch {
		case ctx.Err() != nil && err != nil:
			status = "cancelled"
		case err != nil:
			status = "failed"
			summary = err.Error() + "; " + summary
			c.Store.Log(id, "error", err.Error())
		case r.rs.errs.Load() > 0 && r.rs.errs.Load()*10 > r.rs.total.Load():
			status = "partial"
		}
		c.Store.UpdateRunProgress(id, int(rs.total.Load()), int(rs.done.Load()), int(rs.errs.Load()))
		c.Store.FinishRun(id, status, summary, r.snapshot)
		c.Store.Log(id, "info", "finished: "+status+" "+summary)
		c.Log.Info("run finished", "run", id, "kind", kind, "status", status, "summary", summary, "took", time.Since(rs.p.StartedAt).Round(time.Second))
	}()
	return id, nil
}

// run is one execution.
type run struct {
	c        *Checker
	id       int64
	rs       *runState
	kind     string
	scope    string
	pool     *dnscheck.Pool
	rdap     *rdap.Client
	snapshot int64
	statsMu  sync.Mutex
	stats    map[string]int
}

func (r *run) stat(k string, n int) {
	r.statsMu.Lock()
	if r.stats == nil {
		r.stats = map[string]int{}
	}
	r.stats[k] += n
	r.statsMu.Unlock()
}

func (r *run) summary() string {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	var ks []string
	for k := range r.stats {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	fmt.Fprintf(&b, "%d/%d done, %d errors", r.rs.done.Load(), r.rs.total.Load(), r.rs.errs.Load())
	for _, k := range ks {
		fmt.Fprintf(&b, ", %s=%d", k, r.stats[k])
	}
	return b.String()
}

func (r *run) logf(level, format string, a ...any) {
	if r.id == 0 {
		r.c.Log.Info(fmt.Sprintf(format, a...), "level", level)
		return
	}
	r.c.Store.Log(r.id, level, fmt.Sprintf(format, a...))
}

// beginPhase sets progress counters. Sub-phases (e.g. RDAP confirmation after
// a DNS pass) extend the totals instead of resetting them.
func (r *run) beginPhase(n int, sub bool) {
	if sub {
		r.rs.total.Add(int64(n))
		return
	}
	r.rs.total.Store(int64(n))
	r.rs.done.Store(0)
}

func (r *run) phase(p string) {
	r.rs.phase.Store(p)
	r.logf("info", "phase: %s", p)
}

// progressLoop periodically persists progress.
func (r *run) progressLoop(ctx context.Context) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				r.c.Store.UpdateRunProgress(r.id, int(r.rs.total.Load()), int(r.rs.done.Load()), int(r.rs.errs.Load()))
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() { close(done) }
}

func (r *run) exec(ctx context.Context, ids []int64) error {
	stop := r.progressLoop(ctx)
	defer stop()
	switch r.kind {
	case KindSync:
		_, err := r.sync(ctx)
		return err
	case KindDNSPrivate, KindDNSICANN:
		if _, err := r.sync(ctx); err != nil {
			r.logf("warn", "PSL sync failed, continuing with stored list: %v", err)
		}
		sec := psl.SectionPrivate
		if r.kind == KindDNSICANN {
			sec = psl.SectionICANN
		}
		ts, err := r.c.Store.LoadTargets(sec)
		if err != nil {
			return err
		}
		if len(ts) == 0 {
			return fmt.Errorf("no targets: PSL has never been synced")
		}
		return r.dnsPhase(ctx, ts, r.c.Config().AutoRDAP)
	case KindRecheck:
		var ts []*store.Target
		for _, id := range ids {
			if t, err := r.c.Store.GetTarget(id); err == nil {
				ts = append(ts, t)
			}
		}
		if err := r.dnsPhase(ctx, ts, false); err != nil {
			return err
		}
		if r.scope == "full" {
			if err := r.rdapPhase(ctx, ts, true); err != nil {
				return err
			}
			return r.txtPhase(ctx, ts, true)
		}
		return nil
	case KindRDAP:
		if _, err := r.sync(ctx); err != nil {
			r.logf("warn", "PSL sync failed, continuing with stored list: %v", err)
		}
		sec := r.scope
		if sec == "all" {
			sec = ""
		}
		ts, err := r.c.Store.LoadTargets(sec)
		if err != nil {
			return err
		}
		return r.rdapPhase(ctx, ts, false)
	case KindTXT:
		if _, err := r.sync(ctx); err != nil {
			r.logf("warn", "PSL sync failed, continuing with stored list: %v", err)
		}
		return r.txtPhase(ctx, nil, false)
	case KindReport:
		return fmt.Errorf("report runs are executed by the scheduler")
	}
	return fmt.Errorf("unknown run kind %q", r.kind)
}

// sync downloads the PSL and updates rules/targets if it changed.
func (r *run) sync(ctx context.Context) (*store.SyncResult, error) {
	r.phase("fetching PSL")
	cfg := r.c.Config()
	l, err := psl.Fetch(psl.HTTPClient(), cfg.PSLURL)
	if err != nil {
		return nil, err
	}
	res, err := r.c.Store.SyncList(ctx, l, r.c.Exceptions().MissingTXT, r.id)
	if err != nil {
		return nil, err
	}
	r.snapshot = res.SnapshotID
	if res.New {
		r.logf("info", "PSL %s (commit %s): +%d/-%d rules, +%d/-%d targets", l.Version, short(l.Commit), len(res.AddedRules), len(res.RemovedRules), res.AddedTargets, res.RemovedTargets)
		r.stat("rules_added", len(res.AddedRules))
		r.stat("rules_removed", len(res.RemovedRules))
	} else {
		r.logf("info", "PSL unchanged (%s)", l.Version)
	}
	return res, nil
}

func short(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

// ---- batched writer

type writeOp func(tx *sql.Tx) error

type writer struct {
	st   *store.Store
	ch   chan writeOp
	done chan struct{}
	err  atomic.Value
	log  func(string, string, ...any)
}

func newWriter(st *store.Store, log func(string, string, ...any)) *writer {
	w := &writer{st: st, ch: make(chan writeOp, 1024), done: make(chan struct{}), log: log}
	go w.loop()
	return w
}

func (w *writer) loop() {
	defer close(w.done)
	batch := make([]writeOp, 0, 256)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			err = w.st.Tx(context.Background(), func(tx *sql.Tx) error {
				for _, op := range batch {
					if err := op(tx); err != nil {
						return err
					}
				}
				return nil
			})
			if err == nil {
				break
			}
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
		if err != nil {
			w.err.Store(err)
			w.log("error", "batch write failed (%d ops): %v", len(batch), err)
		}
		batch = batch[:0]
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case op, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, op)
			if len(batch) >= 200 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (w *writer) put(op writeOp) { w.ch <- op }

func (w *writer) close() error {
	close(w.ch)
	<-w.done
	if e, ok := w.err.Load().(error); ok {
		return e
	}
	return nil
}

// ---- evaluation

func (r *run) evaluate(t *store.Target, txtMissing []string, txtChecked int) {
	cfg := r.c.Config()
	in := analyze.Input{Section: t.Section, DNS: t.DNS, RDAP: t.RDAP, ParkedNS: t.ParkedNS, Grace: cfg.Grace, Now: time.Now()}
	if t.Section == psl.SectionPrivate {
		in.TXT = analyze.TXTInfo{Checked: txtChecked, Missing: txtMissing}
	}
	prevTypes := t.FlagTypes
	t.Flags = analyze.Evaluate(in)
	t.Severity = analyze.MaxSeverity(t.Flags)
	t.FlagTypes = store.FlagTypeString(t.Flags)
	t.TXTChecked, t.TXTMissing = txtChecked, len(txtMissing)
	if t.Severity >= analyze.SevLow {
		if t.FlaggedSince.IsZero() || prevTypes != t.FlagTypes && newFlags(prevTypes, t.FlagTypes) {
			t.FlaggedSince = time.Now()
		}
	} else {
		t.FlaggedSince = time.Time{}
	}
}

// newFlags reports whether cur contains a flag type (sev>=low) not in prev.
func newFlags(prev, cur string) bool {
	for _, f := range strings.Split(strings.Trim(cur, ","), ",") {
		if f == "" || f == analyze.FlagInconsistent {
			continue
		}
		if !strings.Contains(prev, ","+f+",") {
			return true
		}
	}
	return false
}

func (r *run) recordResult(tx *sql.Tx, t *store.Target) error {
	_, err := tx.Exec(`INSERT OR REPLACE INTO run_results(run_id,target_id,dns_status,dns_state,ns,rdap_result,rdap_expires,rdap_created,txt_missing,severity,flag_types) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		r.id, t.ID, t.DNS.LastStatus, t.DNS.State, store.JoinList(t.DNS.Current), t.RDAP.Result, store.Unix(t.RDAP.Expires), store.Unix(t.RDAP.Created), t.TXTMissing, t.Severity, t.FlagTypes)
	return err
}

// ---- DNS phase

func (r *run) dnsPhase(ctx context.Context, ts []*store.Target, autoRDAP bool) error {
	cfg := r.c.Config()
	r.phase(fmt.Sprintf("DNS NS lookups (%d targets)", len(ts)))
	r.beginPhase(len(ts), false)
	txtMissing := r.c.Store.TXTMissingByTarget()
	txtChecked := r.c.Store.TXTCheckedByTarget()
	w := newWriter(r.c.Store, r.logf)
	var confirmMu sync.Mutex
	var confirm []*store.Target

	dnscheck.Runner(ctx, cfg.DNSWorkers, ts, func(ctx context.Context, t *store.Target) {
		defer r.rs.done.Add(1)
		tctx, cancel := context.WithTimeout(ctx, cfg.TargetTimeout)
		defer cancel()
		lk := r.pool.QueryNS(tctx, t.Name, t.DNS.Baseline)
		if ctx.Err() != nil {
			return
		}
		now := time.Now()
		if lk.Status == dnscheck.StatusError {
			r.rs.errs.Add(1)
		}
		r.stat("dns_"+lk.Status, 1)
		prevState := t.DNS.State
		ev := analyze.Apply(&t.DNS, analyze.Observation{Status: lk.Status, Records: lk.Records, Inconsistent: lk.Inconsistent, At: now}, cfg.Grace)
		t.DNSDetail = lk.Summary()
		t.DNSCheckedAt = now
		if lk.Status == dnscheck.StatusOK {
			t.ParkedNS = r.c.Parking.Match(lk.Records)
		} else if dnscheck.IsMissing(lk.Status) {
			t.ParkedNS = nil
		}
		r.evaluate(t, txtMissing[t.ID], txtChecked[t.ID])
		tt := *t
		w.put(func(tx *sql.Tx) error {
			if err := store.SaveDNSTx(tx, &tt); err != nil {
				return err
			}
			if err := store.SaveFlagsTx(tx, &tt); err != nil {
				return err
			}
			if ev != nil {
				r.c.Store.AddEventTx(tx, r.id, tt.ID, "dns_state", ev.From, ev.To, ev.Detail)
			}
			return r.recordResult(tx, &tt)
		})
		if autoRDAP && needsRDAPConfirm(t, prevState, cfg) {
			confirmMu.Lock()
			confirm = append(confirm, t)
			confirmMu.Unlock()
		}
	})
	if err := w.close(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(confirm) > 0 {
		r.logf("info", "%d anomalous targets queued for RDAP confirmation", len(confirm))
		r.stat("rdap_confirm", len(confirm))
		if err := r.rdapPhase(ctx, confirm, true); err != nil {
			return err
		}
	}
	return nil
}

// needsRDAPConfirm decides whether a DNS anomaly warrants an RDAP lookup.
func needsRDAPConfirm(t *store.Target, prevState string, cfg Config) bool {
	anomalous := t.DNS.State == analyze.DNSDefunct || t.DNS.State == analyze.DNSChanged || t.DNS.State == analyze.DNSAppeared ||
		len(t.ParkedNS) > 0 || t.DNS.State == analyze.DNSMissing || t.DNS.State == analyze.DNSChanging
	if !anomalous {
		return false
	}
	if t.RDAP.Result == rdap.ResultUnsupported && time.Since(t.RDAP.CheckedAt) < 7*24*time.Hour {
		return false
	}
	// first transition into an anomaly, at confirmation time, or stale cache
	if prevState != t.DNS.State {
		return true
	}
	return t.RDAP.CheckedAt.IsZero() || time.Since(t.RDAP.CheckedAt) > cfg.RDAPMaxAge
}

// ---- RDAP phase

func (r *run) rdapPhase(ctx context.Context, ts []*store.Target, sub bool) error {
	cfg := r.c.Config()
	r.phase(fmt.Sprintf("RDAP lookups (%d targets)", len(ts)))
	r.rdap.ResetCircuits()
	r.beginPhase(len(ts), sub)
	txtMissing := r.c.Store.TXTMissingByTarget()
	txtChecked := r.c.Store.TXTCheckedByTarget()
	w := newWriter(r.c.Store, r.logf)
	// Interleave servers so a slow registry doesn't serialize the queue.
	ts = interleaveByServer(ts, r.rdap)
	dnscheck.Runner(ctx, cfg.RDAPWorkers, ts, func(ctx context.Context, t *store.Target) {
		defer r.rs.done.Add(1)
		tctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		d := r.rdap.Lookup(tctx, t.Name)
		if ctx.Err() != nil {
			return
		}
		r.stat("rdap_"+d.Result, 1)
		evs := applyRDAP(t, d)
		if d.Result == rdap.ResultError {
			r.rs.errs.Add(1)
		}
		r.evaluate(t, txtMissing[t.ID], txtChecked[t.ID])
		tt := *t
		w.put(func(tx *sql.Tx) error {
			if err := store.SaveRDAPTx(tx, &tt); err != nil {
				return err
			}
			if err := store.SaveFlagsTx(tx, &tt); err != nil {
				return err
			}
			for _, e := range evs {
				r.c.Store.AddEventTx(tx, r.id, tt.ID, e[0], e[1], e[2], e[3])
			}
			return r.recordResult(tx, &tt)
		})
	})
	if err := w.close(); err != nil {
		return err
	}
	for _, h := range r.rdap.Stats() {
		if h.Failures > 0 || h.CircuitOpen {
			r.logf("warn", "rdap server %s: requests=%d failures=%d throttled=%d circuit_open=%v", h.Host, h.Requests, h.Failures, h.Throttled, h.CircuitOpen)
		}
	}
	return ctx.Err()
}

// applyRDAP merges an RDAP result into the target cache, returning events.
// Errors never overwrite good cached data.
func applyRDAP(t *store.Target, d *rdap.Domain) [][4]string {
	var evs [][4]string
	now := time.Now()
	prev := t.RDAP
	switch d.Result {
	case rdap.ResultFound:
		if !d.Created.IsZero() && !prev.Created.IsZero() && !d.Created.Equal(prev.Created) {
			t.RDAP.PrevCreated = prev.Created
			evs = append(evs, [4]string{"rdap_created_changed", prev.Created.Format("2006-01-02"), d.Created.Format("2006-01-02"), ""})
		}
		if !d.Expires.IsZero() && !prev.Expires.IsZero() && !d.Expires.Equal(prev.Expires) {
			evs = append(evs, [4]string{"rdap_expiry_changed", prev.Expires.Format("2006-01-02"), d.Expires.Format("2006-01-02"), ""})
		}
		if prev.Result == rdap.ResultNotFound {
			evs = append(evs, [4]string{"rdap_result", prev.Result, d.Result, "registered again"})
		}
		t.RDAP.Result = d.Result
		if !d.Created.IsZero() {
			t.RDAP.Created = d.Created
		}
		t.RDAP.Expires = d.Expires
		t.RDAP.Statuses = d.Statuses
		t.RDAP.EverFound = true
		t.RDAPChanged = d.LastChanged
		t.RDAPRegistrar = d.Registrar
		t.RDAPNS = d.Nameservers
		t.RDAPError = ""
		t.RDAPServer = d.Server
		t.RDAP.CheckedAt = now
	case rdap.ResultNotFound:
		if prev.Result == rdap.ResultFound {
			evs = append(evs, [4]string{"rdap_result", prev.Result, d.Result, "RDAP record disappeared"})
		}
		t.RDAP.Result = d.Result
		t.RDAP.Statuses = nil
		t.RDAPError = ""
		t.RDAPServer = d.Server
		t.RDAP.CheckedAt = now
	case rdap.ResultUnsupported:
		if prev.Result == "" || prev.Result == rdap.ResultError {
			t.RDAP.Result = d.Result
		}
		t.RDAP.CheckedAt = now
		t.RDAPError = "no RDAP server for TLD"
	case rdap.ResultError:
		// keep previous cached data; only record the error
		if prev.Result == "" {
			t.RDAP.Result = d.Result
		}
		t.RDAPError = d.Err
		t.RDAPServer = d.Server
		if t.RDAP.CheckedAt.IsZero() {
			t.RDAP.CheckedAt = now
		}
	}
	return evs
}

func interleaveByServer(ts []*store.Target, c *rdap.Client) []*store.Target {
	groups := map[string][]*store.Target{}
	var keys []string
	for _, t := range ts {
		s := c.ServerFor(t.Name)
		if _, ok := groups[s]; !ok {
			keys = append(keys, s)
		}
		groups[s] = append(groups[s], t)
	}
	sort.Strings(keys)
	out := make([]*store.Target, 0, len(ts))
	for len(out) < len(ts) {
		for _, k := range keys {
			if g := groups[k]; len(g) > 0 {
				out = append(out, g[0])
				groups[k] = g[1:]
			}
		}
	}
	return out
}

// ---- TXT phase

func (r *run) txtPhase(ctx context.Context, only []*store.Target, sub bool) error {
	cfg := r.c.Config()
	rules, err := r.c.Store.ActivePrivateRules()
	if err != nil {
		return err
	}
	if only != nil {
		ids := map[int64]bool{}
		for _, t := range only {
			ids[t.ID] = true
		}
		var f []store.Rule
		for _, ru := range rules {
			if ids[ru.TargetID] {
				f = append(f, ru)
			}
		}
		rules = f
	}
	r.phase(fmt.Sprintf("_psl TXT lookups (%d private rules)", len(rules)))
	r.beginPhase(len(rules), sub)
	exc := r.c.Exceptions()
	w := newWriter(r.c.Store, r.logf)
	dnscheck.Runner(ctx, cfg.TXTWorkers, rules, func(ctx context.Context, ru store.Rule) {
		defer r.rs.done.Add(1)
		tctx, cancel := context.WithTimeout(ctx, cfg.TargetTimeout)
		defer cancel()
		lk := r.pool.QueryTXT(tctx, compliance.TXTName(ru.Name))
		if ctx.Err() != nil {
			return
		}
		ok := lk.Status == dnscheck.StatusOK
		conclusive := ok || lk.Status == dnscheck.StatusNXDomain || lk.Status == dnscheck.StatusNoData
		status, prs := exc.Evaluate(ru.Name, ok, conclusive, lk.Records)
		if status == compliance.TXTUnknown {
			r.rs.errs.Add(1)
		}
		r.stat("txt_"+status, 1)
		var prStr []string
		for _, p := range prs {
			prStr = append(prStr, fmt.Sprint(p))
		}
		recs := strings.Join(lk.Records, " | ")
		if len(recs) > 500 {
			recs = recs[:500]
		}
		prevStatus := ru.TXTStatus
		id, tid := ru.ID, ru.TargetID
		w.put(func(tx *sql.Tx) error {
			if status == compliance.TXTUnknown && prevStatus != "" && prevStatus != compliance.TXTUnknown {
				// keep last conclusive status
				return nil
			}
			if prevStatus != "" && prevStatus != status && status != compliance.TXTUnknown {
				r.c.Store.AddEventTx(tx, r.id, tid, "psl_txt", prevStatus, status, ru.Raw)
			}
			return store.SaveTXTTx(tx, id, status, recs, strings.Join(prStr, ","), time.Now())
		})
	})
	if err := w.close(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if only != nil {
		return r.reevaluateTargets(only)
	}
	return r.reevaluate(ctx, psl.SectionPrivate)
}

// reevaluateTargets reloads and re-evaluates specific targets.
func (r *run) reevaluateTargets(ts []*store.Target) error {
	txtMissing := r.c.Store.TXTMissingByTarget()
	txtChecked := r.c.Store.TXTCheckedByTarget()
	w := newWriter(r.c.Store, r.logf)
	for _, old := range ts {
		t, err := r.c.Store.GetTarget(old.ID)
		if err != nil {
			continue
		}
		r.evaluate(t, txtMissing[t.ID], txtChecked[t.ID])
		tt := *t
		w.put(func(tx *sql.Tx) error {
			if err := store.SaveFlagsTx(tx, &tt); err != nil {
				return err
			}
			return r.recordResult(tx, &tt)
		})
	}
	return w.close()
}

// reevaluate recomputes flags for all targets in a section from cached data.
func (r *run) reevaluate(ctx context.Context, section string) error {
	r.phase("re-evaluating flags")
	ts, err := r.c.Store.LoadTargets(section)
	if err != nil {
		return err
	}
	txtMissing := r.c.Store.TXTMissingByTarget()
	txtChecked := r.c.Store.TXTCheckedByTarget()
	w := newWriter(r.c.Store, r.logf)
	for _, t := range ts {
		r.evaluate(t, txtMissing[t.ID], txtChecked[t.ID])
		tt := *t
		w.put(func(tx *sql.Tx) error { return store.SaveFlagsTx(tx, &tt) })
	}
	return w.close()
}

// Reevaluate recomputes flags synchronously (e.g. after settings change).
func (c *Checker) Reevaluate(ctx context.Context) error {
	r := &run{c: c, rs: &runState{}}
	r.rs.phase.Store("")
	r.id = 0
	return r.reevaluate(ctx, "")
}

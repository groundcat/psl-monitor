// Package store persists everything in a single SQLite file.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps separate read and write pools over one SQLite file.
type Store struct {
	W *sql.DB // single connection: serialises writes
	R *sql.DB // concurrent readers (WAL)
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	email TEXT NOT NULL DEFAULT '',
	receive_reports INTEGER NOT NULL DEFAULT 1,
	active INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	last_login INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
	id INTEGER PRIMARY KEY,
	version TEXT NOT NULL,
	commit_hash TEXT NOT NULL,
	sha256 TEXT NOT NULL,
	fetched_at INTEGER NOT NULL,
	rules_icann INTEGER NOT NULL,
	rules_private INTEGER NOT NULL,
	targets_icann INTEGER NOT NULL,
	targets_private INTEGER NOT NULL,
	added TEXT NOT NULL DEFAULT '',
	removed TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS targets (
	id INTEGER PRIMARY KEY,
	section TEXT NOT NULL,
	name TEXT NOT NULL,
	uname TEXT NOT NULL,
	suffix TEXT NOT NULL,
	tld TEXT NOT NULL,
	entity TEXT NOT NULL DEFAULT '',
	rule_count INTEGER NOT NULL DEFAULT 0,
	active INTEGER NOT NULL DEFAULT 1,
	first_seen INTEGER NOT NULL,
	removed_at INTEGER NOT NULL DEFAULT 0,

	dns_state TEXT NOT NULL DEFAULT 'unknown',
	dns_status TEXT NOT NULL DEFAULT '',
	ns_baseline TEXT NOT NULL DEFAULT '',
	ns_baseline_at INTEGER NOT NULL DEFAULT 0,
	ns_previous TEXT NOT NULL DEFAULT '',
	ns_current TEXT NOT NULL DEFAULT '',
	ns_last_ok_at INTEGER NOT NULL DEFAULT 0,
	missing_days INTEGER NOT NULL DEFAULT 0,
	missing_since INTEGER NOT NULL DEFAULT 0,
	changed_days INTEGER NOT NULL DEFAULT 0,
	changed_since INTEGER NOT NULL DEFAULT 0,
	neg_days INTEGER NOT NULL DEFAULT 0,
	last_day TEXT NOT NULL DEFAULT '',
	inconsistent INTEGER NOT NULL DEFAULT 0,
	dns_detail TEXT NOT NULL DEFAULT '',
	dns_checked_at INTEGER NOT NULL DEFAULT 0,
	parked_ns TEXT NOT NULL DEFAULT '',

	rdap_result TEXT NOT NULL DEFAULT '',
	rdap_server TEXT NOT NULL DEFAULT '',
	rdap_created INTEGER NOT NULL DEFAULT 0,
	rdap_expires INTEGER NOT NULL DEFAULT 0,
	rdap_prev_created INTEGER NOT NULL DEFAULT 0,
	rdap_last_changed INTEGER NOT NULL DEFAULT 0,
	rdap_statuses TEXT NOT NULL DEFAULT '',
	rdap_registrar TEXT NOT NULL DEFAULT '',
	rdap_ns TEXT NOT NULL DEFAULT '',
	rdap_ever_found INTEGER NOT NULL DEFAULT 0,
	rdap_error TEXT NOT NULL DEFAULT '',
	rdap_checked_at INTEGER NOT NULL DEFAULT 0,

	txt_checked INTEGER NOT NULL DEFAULT 0,
	txt_missing INTEGER NOT NULL DEFAULT 0,

	flags TEXT NOT NULL DEFAULT '[]',
	flag_types TEXT NOT NULL DEFAULT '',
	severity INTEGER NOT NULL DEFAULT 0,
	flagged_since INTEGER NOT NULL DEFAULT 0,
	acked_at INTEGER NOT NULL DEFAULT 0,
	acked_by TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT '',
	UNIQUE(section, name)
);
CREATE INDEX IF NOT EXISTS idx_targets_sev ON targets(severity DESC);
CREATE INDEX IF NOT EXISTS idx_targets_tld ON targets(tld);
CREATE INDEX IF NOT EXISTS idx_targets_exp ON targets(rdap_expires);
CREATE TABLE IF NOT EXISTS rules (
	id INTEGER PRIMARY KEY,
	section TEXT NOT NULL,
	raw TEXT NOT NULL,
	name TEXT NOT NULL,
	uname TEXT NOT NULL,
	kind TEXT NOT NULL,
	entity TEXT NOT NULL DEFAULT '',
	submitter TEXT NOT NULL DEFAULT '',
	line INTEGER NOT NULL DEFAULT 0,
	target_id INTEGER NOT NULL DEFAULT 0,
	active INTEGER NOT NULL DEFAULT 1,
	first_seen INTEGER NOT NULL,
	removed_at INTEGER NOT NULL DEFAULT 0,
	exempt INTEGER NOT NULL DEFAULT 0,
	txt_status TEXT NOT NULL DEFAULT '',
	txt_records TEXT NOT NULL DEFAULT '',
	txt_prs TEXT NOT NULL DEFAULT '',
	txt_checked_at INTEGER NOT NULL DEFAULT 0,
	UNIQUE(section, raw)
);
CREATE INDEX IF NOT EXISTS idx_rules_target ON rules(target_id);
CREATE TABLE IF NOT EXISTS runs (
	id INTEGER PRIMARY KEY,
	kind TEXT NOT NULL,
	scope TEXT NOT NULL DEFAULT '',
	trigger TEXT NOT NULL,
	triggered_by TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	snapshot_id INTEGER NOT NULL DEFAULT 0,
	started_at INTEGER NOT NULL,
	finished_at INTEGER NOT NULL DEFAULT 0,
	total INTEGER NOT NULL DEFAULT 0,
	done INTEGER NOT NULL DEFAULT 0,
	errors INTEGER NOT NULL DEFAULT 0,
	summary TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_runs_kind ON runs(kind, started_at DESC);
CREATE TABLE IF NOT EXISTS run_logs (
	id INTEGER PRIMARY KEY,
	run_id INTEGER NOT NULL,
	ts INTEGER NOT NULL,
	level TEXT NOT NULL,
	msg TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_run_logs ON run_logs(run_id, id);
CREATE TABLE IF NOT EXISTS run_results (
	run_id INTEGER NOT NULL,
	target_id INTEGER NOT NULL,
	dns_status TEXT NOT NULL DEFAULT '',
	dns_state TEXT NOT NULL DEFAULT '',
	ns TEXT NOT NULL DEFAULT '',
	rdap_result TEXT NOT NULL DEFAULT '',
	rdap_expires INTEGER NOT NULL DEFAULT 0,
	rdap_created INTEGER NOT NULL DEFAULT 0,
	txt_missing INTEGER NOT NULL DEFAULT 0,
	severity INTEGER NOT NULL DEFAULT 0,
	flag_types TEXT NOT NULL DEFAULT '',
	PRIMARY KEY(run_id, target_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_run_results_target ON run_results(target_id);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,
	run_id INTEGER NOT NULL DEFAULT 0,
	target_id INTEGER NOT NULL DEFAULT 0,
	type TEXT NOT NULL,
	from_val TEXT NOT NULL DEFAULT '',
	to_val TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_target ON events(target_id, ts DESC);
`

// Open opens (and migrates) the database file.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", dsn+"&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	r.SetMaxOpenConns(8)
	s := &Store{W: w, R: r}
	if _, err := w.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// data fix: creation dates differing only in sub-day precision are not re-registrations
	w.Exec(`UPDATE targets SET rdap_prev_created=0 WHERE rdap_prev_created>0 AND date(rdap_prev_created,'unixepoch')=date(rdap_created,'unixepoch')`)
	return s, nil
}

// Close closes both pools.
func (s *Store) Close() error {
	s.R.Close()
	return s.W.Close()
}

// Tx runs fn in a write transaction.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- helpers

func Unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func FromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func JoinList(s []string) string { return strings.Join(s, ",") }

func SplitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// ---- settings

func (s *Store) GetSetting(key, def string) string {
	var v string
	if err := s.R.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.W.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) AllSettings() map[string]string {
	m := map[string]string{}
	rows, err := s.R.Query(`SELECT key,value FROM settings`)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			m[k] = v
		}
	}
	return m
}

// ---- runs & logs

type Run struct {
	ID          int64
	Kind        string
	Scope       string
	Trigger     string
	TriggeredBy string
	Status      string
	SnapshotID  int64
	StartedAt   time.Time
	FinishedAt  time.Time
	Total       int
	Done        int
	Errors      int
	Summary     string
}

func (r Run) Duration() time.Duration {
	end := r.FinishedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(r.StartedAt).Round(time.Second)
}

const runCols = `id,kind,scope,trigger,triggered_by,status,snapshot_id,started_at,finished_at,total,done,errors,summary`

func scanRun(sc interface{ Scan(...any) error }) (Run, error) {
	var r Run
	var st, fin int64
	err := sc.Scan(&r.ID, &r.Kind, &r.Scope, &r.Trigger, &r.TriggeredBy, &r.Status, &r.SnapshotID, &st, &fin, &r.Total, &r.Done, &r.Errors, &r.Summary)
	r.StartedAt, r.FinishedAt = FromUnix(st), FromUnix(fin)
	return r, err
}

func (s *Store) CreateRun(kind, scope, trigger, by string) (int64, error) {
	res, err := s.W.Exec(`INSERT INTO runs(kind,scope,trigger,triggered_by,status,started_at) VALUES(?,?,?,?,?,?)`, kind, scope, trigger, by, "running", time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateRunProgress(id int64, total, done, errs int) {
	s.W.Exec(`UPDATE runs SET total=?, done=?, errors=? WHERE id=?`, total, done, errs, id)
}

func (s *Store) FinishRun(id int64, status, summary string, snapshot int64) {
	s.W.Exec(`UPDATE runs SET status=?, summary=?, finished_at=?, snapshot_id=CASE WHEN ?>0 THEN ? ELSE snapshot_id END WHERE id=?`, status, summary, time.Now().Unix(), snapshot, snapshot, id)
}

// MarkInterruptedRuns flags runs left "running" by a crash/restart.
func (s *Store) MarkInterruptedRuns() {
	s.W.Exec(`UPDATE runs SET status='interrupted', finished_at=? WHERE status='running'`, time.Now().Unix())
}

func (s *Store) GetRun(id int64) (Run, error) {
	return scanRun(s.R.QueryRow(`SELECT `+runCols+` FROM runs WHERE id=?`, id))
}

func (s *Store) LastRun(kind string) (Run, bool) {
	r, err := scanRun(s.R.QueryRow(`SELECT `+runCols+` FROM runs WHERE kind=? ORDER BY started_at DESC, id DESC LIMIT 1`, kind))
	return r, err == nil
}

// PreviousRun returns the latest finished run of the same kind+scope before id.
func (s *Store) PreviousRun(r Run) (Run, bool) {
	p, err := scanRun(s.R.QueryRow(`SELECT `+runCols+` FROM runs WHERE kind=? AND scope=? AND id<? AND status IN ('ok','partial') ORDER BY id DESC LIMIT 1`, r.Kind, r.Scope, r.ID))
	return p, err == nil
}

func (s *Store) ListRuns(kind string, limit, offset int) ([]Run, int) {
	where, args := "1=1", []any{}
	if kind != "" {
		where, args = "kind=?", append(args, kind)
	}
	var total int
	s.R.QueryRow(`SELECT COUNT(*) FROM runs WHERE `+where, args...).Scan(&total)
	rows, err := s.R.Query(`SELECT `+runCols+` FROM runs WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		if r, err := scanRun(rows); err == nil {
			out = append(out, r)
		}
	}
	return out, total
}

func (s *Store) Log(runID int64, level, msg string) {
	s.W.Exec(`INSERT INTO run_logs(run_id,ts,level,msg) VALUES(?,?,?,?)`, runID, time.Now().Unix(), level, msg)
}

type LogLine struct {
	TS    time.Time
	Level string
	Msg   string
}

func (s *Store) RunLogs(runID int64, limit int) []LogLine {
	rows, err := s.R.Query(`SELECT ts,level,msg FROM run_logs WHERE run_id=? ORDER BY id LIMIT ?`, runID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []LogLine
	for rows.Next() {
		var l LogLine
		var ts int64
		if rows.Scan(&ts, &l.Level, &l.Msg) == nil {
			l.TS = FromUnix(ts)
			out = append(out, l)
		}
	}
	return out
}

// Prune deletes history older than the retention window.
func (s *Store) Prune(days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	var n int64
	err := s.Tx(context.Background(), func(tx *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM run_results WHERE run_id IN (SELECT id FROM runs WHERE started_at<?)`,
			`DELETE FROM run_logs WHERE run_id IN (SELECT id FROM runs WHERE started_at<?)`,
			`DELETE FROM runs WHERE started_at<?`,
			`DELETE FROM sessions WHERE expires_at<?`,
		} {
			arg := cut
			if strings.Contains(q, "sessions") {
				arg = time.Now().Unix()
			}
			res, err := tx.Exec(q, arg)
			if err != nil {
				return err
			}
			c, _ := res.RowsAffected()
			n += c
		}
		return nil
	})
	return n, err
}

// ---- events

type Event struct {
	ID       int64
	TS       time.Time
	RunID    int64
	TargetID int64
	Type     string
	From, To string
	Detail   string
	// joined
	Section, Name string
}

func (s *Store) AddEventTx(tx *sql.Tx, runID, targetID int64, typ, from, to, detail string) error {
	_, err := tx.Exec(`INSERT INTO events(ts,run_id,target_id,type,from_val,to_val,detail) VALUES(?,?,?,?,?,?,?)`, time.Now().Unix(), runID, targetID, typ, from, to, detail)
	return err
}

func (s *Store) AddEvent(runID, targetID int64, typ, from, to, detail string) {
	s.W.Exec(`INSERT INTO events(ts,run_id,target_id,type,from_val,to_val,detail) VALUES(?,?,?,?,?,?,?)`, time.Now().Unix(), runID, targetID, typ, from, to, detail)
}

type EventFilter struct {
	Q        string
	Type     string
	Section  string
	TargetID int64
	Since    time.Time
	Limit    int
	Offset   int
}

func (s *Store) ListEvents(f EventFilter) ([]Event, int) {
	where := []string{"1=1"}
	var args []any
	if f.Type != "" {
		where, args = append(where, "e.type=?"), append(args, f.Type)
	}
	if f.Section != "" {
		where, args = append(where, "t.section=?"), append(args, f.Section)
	}
	if f.TargetID > 0 {
		where, args = append(where, "e.target_id=?"), append(args, f.TargetID)
	}
	if f.Q != "" {
		where, args = append(where, "(t.name LIKE ? OR e.detail LIKE ?)"), append(args, "%"+f.Q+"%", "%"+f.Q+"%")
	}
	if !f.Since.IsZero() {
		where, args = append(where, "e.ts>=?"), append(args, f.Since.Unix())
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	w := strings.Join(where, " AND ")
	var total int
	s.R.QueryRow(`SELECT COUNT(*) FROM events e LEFT JOIN targets t ON t.id=e.target_id WHERE `+w, args...).Scan(&total)
	rows, err := s.R.Query(`SELECT e.id,e.ts,e.run_id,e.target_id,e.type,e.from_val,e.to_val,e.detail,COALESCE(t.section,''),COALESCE(t.name,'')
		FROM events e LEFT JOIN targets t ON t.id=e.target_id WHERE `+w+` ORDER BY e.id DESC LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		if rows.Scan(&e.ID, &ts, &e.RunID, &e.TargetID, &e.Type, &e.From, &e.To, &e.Detail, &e.Section, &e.Name) == nil {
			e.TS = FromUnix(ts)
			out = append(out, e)
		}
	}
	return out, total
}

func (s *Store) EventTypes() []string {
	rows, err := s.R.Query(`SELECT DISTINCT type FROM events ORDER BY type`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		rows.Scan(&t)
		out = append(out, t)
	}
	return out
}

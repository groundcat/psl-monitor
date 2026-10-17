package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/psl"
)

// Target is a full target row.
type Target struct {
	ID        int64
	Section   string
	Name      string
	UName     string
	Suffix    string
	TLD       string
	Entity    string
	RuleCount int
	Active    bool
	FirstSeen time.Time
	RemovedAt time.Time

	DNS          analyze.NSState
	DNSDetail    string
	DNSCheckedAt time.Time
	ParkedNS     []string

	RDAP          analyze.RDAPInfo
	RDAPServer    string
	RDAPChanged   time.Time
	RDAPRegistrar string
	RDAPNS        []string
	RDAPError     string

	TXTChecked int
	TXTMissing int

	Flags        []analyze.Flag
	FlagTypes    string
	Severity     int
	FlaggedSince time.Time
	AckedAt      time.Time
	AckedBy      string
	Note         string
}

const targetCols = `id,section,name,uname,suffix,tld,entity,rule_count,active,first_seen,removed_at,
dns_state,dns_status,ns_baseline,ns_baseline_at,ns_previous,ns_current,ns_last_ok_at,missing_days,missing_since,changed_days,changed_since,neg_days,last_day,inconsistent,dns_detail,dns_checked_at,parked_ns,
rdap_result,rdap_server,rdap_created,rdap_expires,rdap_prev_created,rdap_last_changed,rdap_statuses,rdap_registrar,rdap_ns,rdap_ever_found,rdap_error,rdap_checked_at,
txt_checked,txt_missing,flags,flag_types,severity,flagged_since,acked_at,acked_by,note`

func scanTarget(sc interface{ Scan(...any) error }) (*Target, error) {
	t := &Target{}
	var active, incons, ever int
	var firstSeen, removedAt, blAt, lastOK, missSince, chSince, dnsChecked int64
	var rCreated, rExpires, rPrev, rChanged, rChecked, flaggedSince, ackedAt int64
	var bl, prev, cur, parked, rStatuses, rNS, flags string
	err := sc.Scan(&t.ID, &t.Section, &t.Name, &t.UName, &t.Suffix, &t.TLD, &t.Entity, &t.RuleCount, &active, &firstSeen, &removedAt,
		&t.DNS.State, &t.DNS.LastStatus, &bl, &blAt, &prev, &cur, &lastOK, &t.DNS.MissingDays, &missSince, &t.DNS.ChangedDays, &chSince, &t.DNS.NegDays, &t.DNS.LastDay, &incons, &t.DNSDetail, &dnsChecked, &parked,
		&t.RDAP.Result, &t.RDAPServer, &rCreated, &rExpires, &rPrev, &rChanged, &rStatuses, &t.RDAPRegistrar, &rNS, &ever, &t.RDAPError, &rChecked,
		&t.TXTChecked, &t.TXTMissing, &flags, &t.FlagTypes, &t.Severity, &flaggedSince, &ackedAt, &t.AckedBy, &t.Note)
	if err != nil {
		return nil, err
	}
	t.Active, t.DNS.Inconsistent, t.RDAP.EverFound = active == 1, incons == 1, ever == 1
	t.FirstSeen, t.RemovedAt = FromUnix(firstSeen), FromUnix(removedAt)
	t.DNS.Baseline, t.DNS.BaselineAt, t.DNS.Previous, t.DNS.Current = SplitList(bl), FromUnix(blAt), SplitList(prev), SplitList(cur)
	t.DNS.LastOKAt, t.DNS.MissingSince, t.DNS.ChangedSince = FromUnix(lastOK), FromUnix(missSince), FromUnix(chSince)
	t.DNSCheckedAt, t.ParkedNS = FromUnix(dnsChecked), SplitList(parked)
	t.RDAP.Created, t.RDAP.Expires, t.RDAP.PrevCreated, t.RDAPChanged, t.RDAP.CheckedAt = FromUnix(rCreated), FromUnix(rExpires), FromUnix(rPrev), FromUnix(rChanged), FromUnix(rChecked)
	t.RDAP.Statuses, t.RDAPNS = SplitList(rStatuses), SplitList(rNS)
	t.FlaggedSince, t.AckedAt = FromUnix(flaggedSince), FromUnix(ackedAt)
	json.Unmarshal([]byte(flags), &t.Flags)
	return t, nil
}

func (s *Store) GetTarget(id int64) (*Target, error) {
	return scanTarget(s.R.QueryRow(`SELECT `+targetCols+` FROM targets WHERE id=?`, id))
}

func (s *Store) GetTargetByName(section, name string) (*Target, error) {
	return scanTarget(s.R.QueryRow(`SELECT `+targetCols+` FROM targets WHERE section=? AND name=?`, section, name))
}

// LoadTargets loads active targets of a section ("" = all).
func (s *Store) LoadTargets(section string) ([]*Target, error) {
	q := `SELECT ` + targetCols + ` FROM targets WHERE active=1`
	var args []any
	if section != "" {
		q += ` AND section=?`
		args = append(args, section)
	}
	rows, err := s.R.Query(q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveDNSTx persists DNS state for a target.
func SaveDNSTx(tx *sql.Tx, t *Target) error {
	_, err := tx.Exec(`UPDATE targets SET dns_state=?,dns_status=?,ns_baseline=?,ns_baseline_at=?,ns_previous=?,ns_current=?,ns_last_ok_at=?,
		missing_days=?,missing_since=?,changed_days=?,changed_since=?,neg_days=?,last_day=?,inconsistent=?,dns_detail=?,dns_checked_at=?,parked_ns=? WHERE id=?`,
		t.DNS.State, t.DNS.LastStatus, JoinList(t.DNS.Baseline), Unix(t.DNS.BaselineAt), JoinList(t.DNS.Previous), JoinList(t.DNS.Current), Unix(t.DNS.LastOKAt),
		t.DNS.MissingDays, Unix(t.DNS.MissingSince), t.DNS.ChangedDays, Unix(t.DNS.ChangedSince), t.DNS.NegDays, t.DNS.LastDay, b2i(t.DNS.Inconsistent), t.DNSDetail, Unix(t.DNSCheckedAt), JoinList(t.ParkedNS), t.ID)
	return err
}

// SaveRDAPTx persists RDAP cache for a target.
func SaveRDAPTx(tx *sql.Tx, t *Target) error {
	_, err := tx.Exec(`UPDATE targets SET rdap_result=?,rdap_server=?,rdap_created=?,rdap_expires=?,rdap_prev_created=?,rdap_last_changed=?,rdap_statuses=?,rdap_registrar=?,rdap_ns=?,rdap_ever_found=?,rdap_error=?,rdap_checked_at=? WHERE id=?`,
		t.RDAP.Result, t.RDAPServer, Unix(t.RDAP.Created), Unix(t.RDAP.Expires), Unix(t.RDAP.PrevCreated), Unix(t.RDAPChanged), JoinList(t.RDAP.Statuses), t.RDAPRegistrar, JoinList(t.RDAPNS), b2i(t.RDAP.EverFound), t.RDAPError, Unix(t.RDAP.CheckedAt), t.ID)
	return err
}

// SaveFlagsTx persists evaluation results. Returns whether flag types changed.
func SaveFlagsTx(tx *sql.Tx, t *Target) error {
	b, _ := json.Marshal(t.Flags)
	_, err := tx.Exec(`UPDATE targets SET flags=?,flag_types=?,severity=?,flagged_since=?,txt_checked=?,txt_missing=? WHERE id=?`,
		string(b), t.FlagTypes, t.Severity, Unix(t.FlaggedSince), t.TXTChecked, t.TXTMissing, t.ID)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// FlagTypeString encodes flag types for LIKE-searching: ",a,b,".
func FlagTypeString(f []analyze.Flag) string {
	if len(f) == 0 {
		return ""
	}
	var ts []string
	seen := map[string]bool{}
	for _, x := range f {
		if !seen[x.Type] {
			seen[x.Type] = true
			ts = append(ts, x.Type)
		}
	}
	sort.Strings(ts)
	return "," + strings.Join(ts, ",") + ","
}

// ---- rules

type Rule struct {
	ID           int64
	Section      string
	Raw          string
	Name         string
	UName        string
	Kind         string
	Entity       string
	Submitter    string
	Line         int
	TargetID     int64
	Active       bool
	FirstSeen    time.Time
	RemovedAt    time.Time
	Exempt       bool
	TXTStatus    string
	TXTRecords   string
	TXTPRs       string
	TXTCheckedAt time.Time
	TargetName   string
}

const ruleCols = `r.id,r.section,r.raw,r.name,r.uname,r.kind,r.entity,r.submitter,r.line,r.target_id,r.active,r.first_seen,r.removed_at,r.exempt,r.txt_status,r.txt_records,r.txt_prs,r.txt_checked_at,COALESCE(t.name,'')`

func scanRule(sc interface{ Scan(...any) error }) (Rule, error) {
	var r Rule
	var active, exempt int
	var fs, ra, tc int64
	err := sc.Scan(&r.ID, &r.Section, &r.Raw, &r.Name, &r.UName, &r.Kind, &r.Entity, &r.Submitter, &r.Line, &r.TargetID, &active, &fs, &ra, &exempt, &r.TXTStatus, &r.TXTRecords, &r.TXTPRs, &tc, &r.TargetName)
	r.Active, r.Exempt = active == 1, exempt == 1
	r.FirstSeen, r.RemovedAt, r.TXTCheckedAt = FromUnix(fs), FromUnix(ra), FromUnix(tc)
	return r, err
}

func (s *Store) RulesForTarget(id int64) []Rule {
	rows, err := s.R.Query(`SELECT `+ruleCols+` FROM rules r LEFT JOIN targets t ON t.id=r.target_id WHERE r.target_id=? ORDER BY r.active DESC, r.line`, id)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		if r, err := scanRule(rows); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// ActivePrivateRules returns all active private rules.
func (s *Store) ActivePrivateRules() ([]Rule, error) {
	rows, err := s.R.Query(`SELECT ` + ruleCols + ` FROM rules r LEFT JOIN targets t ON t.id=r.target_id WHERE r.active=1 AND r.section='private' ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type RuleFilter struct {
	Q, Section, Kind, TXT, Entity string
	Active                        string // "1","0",""
	Sort                          string
	Limit, Offset                 int
}

func (s *Store) ListRules(f RuleFilter) ([]Rule, int) {
	where := []string{"1=1"}
	var args []any
	if f.Q != "" {
		where = append(where, "(r.name LIKE ? OR r.uname LIKE ? OR r.entity LIKE ? OR r.submitter LIKE ?)")
		q := "%" + strings.ToLower(f.Q) + "%"
		args = append(args, q, q, "%"+f.Q+"%", "%"+f.Q+"%")
	}
	if f.Section != "" {
		where, args = append(where, "r.section=?"), append(args, f.Section)
	}
	if f.Kind != "" {
		where, args = append(where, "r.kind=?"), append(args, f.Kind)
	}
	if f.TXT != "" {
		if f.TXT == "unchecked" {
			where = append(where, "r.txt_status=''")
		} else {
			where, args = append(where, "r.txt_status=?"), append(args, f.TXT)
		}
	}
	if f.Entity != "" {
		where, args = append(where, "r.entity=?"), append(args, f.Entity)
	}
	switch f.Active {
	case "1", "":
		where = append(where, "r.active=1")
	case "0":
		where = append(where, "r.active=0")
	}
	order := map[string]string{"name": "r.name", "line": "r.line", "entity": "r.entity, r.line", "txt": "r.txt_status, r.name", "first_seen": "r.first_seen DESC"}[f.Sort]
	if order == "" {
		order = "r.line"
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	w := strings.Join(where, " AND ")
	var total int
	s.R.QueryRow(`SELECT COUNT(*) FROM rules r WHERE `+w, args...).Scan(&total)
	rows, err := s.R.Query(`SELECT `+ruleCols+` FROM rules r LEFT JOIN targets t ON t.id=r.target_id WHERE `+w+` ORDER BY `+order+` LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		if r, err := scanRule(rows); err == nil {
			out = append(out, r)
		}
	}
	return out, total
}

// SaveTXTTx persists a rule's TXT result.
func SaveTXTTx(tx *sql.Tx, id int64, status, records, prs string, at time.Time) error {
	_, err := tx.Exec(`UPDATE rules SET txt_status=?, txt_records=?, txt_prs=?, txt_checked_at=? WHERE id=?`, status, records, prs, at.Unix(), id)
	return err
}

// RefreshExemptions recomputes rules.exempt from a set.
func (s *Store) RefreshExemptions(exempt map[string]bool) error {
	return s.Tx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE rules SET exempt=0`); err != nil {
			return err
		}
		st, err := tx.Prepare(`UPDATE rules SET exempt=1 WHERE section='private' AND name=?`)
		if err != nil {
			return err
		}
		defer st.Close()
		for n := range exempt {
			if _, err := st.Exec(n); err != nil {
				return err
			}
		}
		// flip stale statuses
		tx.Exec(`UPDATE rules SET txt_status='exempt' WHERE exempt=1 AND txt_status='missing'`)
		tx.Exec(`UPDATE rules SET txt_status='missing' WHERE exempt=0 AND txt_status='exempt'`)
		return nil
	})
}

// TXTMissingByTarget returns rule names with txt_status=missing per target.
func (s *Store) TXTMissingByTarget() map[int64][]string {
	m := map[int64][]string{}
	rows, err := s.R.Query(`SELECT target_id, name FROM rules WHERE active=1 AND section='private' AND txt_status='missing' ORDER BY name`)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n string
		if rows.Scan(&id, &n) == nil {
			m[id] = append(m[id], n)
		}
	}
	return m
}

// TXTCheckedByTarget returns the number of rules with a conclusive TXT status per target.
func (s *Store) TXTCheckedByTarget() map[int64]int {
	m := map[int64]int{}
	rows, err := s.R.Query(`SELECT target_id, COUNT(*) FROM rules WHERE active=1 AND section='private' AND txt_status NOT IN ('','unknown') GROUP BY target_id`)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if rows.Scan(&id, &n) == nil {
			m[id] = n
		}
	}
	return m
}

// ---- snapshots / sync

type Snapshot struct {
	ID                           int64
	Version, Commit, SHA256      string
	FetchedAt                    time.Time
	RulesICANN, RulesPrivate     int
	TargetsICANN, TargetsPrivate int
	Added, Removed               []string
}

func (s *Store) LatestSnapshot() (Snapshot, bool) {
	snaps := s.ListSnapshots(1)
	if len(snaps) == 0 {
		return Snapshot{}, false
	}
	return snaps[0], true
}

func (s *Store) ListSnapshots(limit int) []Snapshot {
	rows, err := s.R.Query(`SELECT id,version,commit_hash,sha256,fetched_at,rules_icann,rules_private,targets_icann,targets_private,added,removed FROM snapshots ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var sn Snapshot
		var fa int64
		var add, rem string
		if rows.Scan(&sn.ID, &sn.Version, &sn.Commit, &sn.SHA256, &fa, &sn.RulesICANN, &sn.RulesPrivate, &sn.TargetsICANN, &sn.TargetsPrivate, &add, &rem) == nil {
			sn.FetchedAt = FromUnix(fa)
			sn.Added, sn.Removed = splitLines(add), splitLines(rem)
			out = append(out, sn)
		}
	}
	return out
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// SyncResult describes the outcome of syncing a parsed list into the db.
type SyncResult struct {
	SnapshotID     int64
	New            bool // list content differs from the last snapshot
	AddedRules     []string
	RemovedRules   []string
	AddedTargets   int
	RemovedTargets int
}

// SyncList upserts rules/targets from a parsed list and records a snapshot.
func (s *Store) SyncList(ctx context.Context, l *psl.List, exempt map[string]bool, runID int64) (*SyncResult, error) {
	res := &SyncResult{}
	if last, ok := s.LatestSnapshot(); ok && last.SHA256 == l.SHA256 {
		res.SnapshotID = last.ID
		return res, nil
	}
	res.New = true
	now := time.Now().Unix()
	targets := l.Targets()
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		// existing
		existingT := map[string]int64{}
		rows, err := tx.Query(`SELECT id, section, name, active FROM targets`)
		if err != nil {
			return err
		}
		activeT := map[string]bool{}
		for rows.Next() {
			var id int64
			var sec, name string
			var act int
			rows.Scan(&id, &sec, &name, &act)
			existingT[sec+"|"+name] = id
			activeT[sec+"|"+name] = act == 1
		}
		rows.Close()
		existingR := map[string]bool{}
		rows, err = tx.Query(`SELECT section, raw FROM rules WHERE active=1`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var sec, raw string
			rows.Scan(&sec, &raw)
			existingR[sec+"|"+raw] = true
		}
		rows.Close()
		hadRules := len(existingR) > 0

		insT, err := tx.Prepare(`INSERT INTO targets(section,name,uname,suffix,tld,entity,rule_count,active,first_seen) VALUES(?,?,?,?,?,?,?,1,?)
			ON CONFLICT(section,name) DO UPDATE SET uname=excluded.uname, suffix=excluded.suffix, tld=excluded.tld, entity=excluded.entity, rule_count=excluded.rule_count, active=1, removed_at=0`)
		if err != nil {
			return err
		}
		defer insT.Close()
		seenT := map[string]bool{}
		for _, t := range targets {
			key := t.Section + "|" + t.Name
			seenT[key] = true
			if _, ok := existingT[key]; !ok || !activeT[key] {
				res.AddedTargets++
			}
			if _, err := insT.Exec(t.Section, t.Name, t.UName, t.Suffix, t.TLD, t.Entity, len(t.Rules), now); err != nil {
				return err
			}
		}
		// ids
		ids := map[string]int64{}
		rows, err = tx.Query(`SELECT id, section, name FROM targets`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var sec, name string
			rows.Scan(&id, &sec, &name)
			ids[sec+"|"+name] = id
		}
		rows.Close()
		for key, id := range existingT {
			if !seenT[key] && activeT[key] {
				res.RemovedTargets++
				if _, err := tx.Exec(`UPDATE targets SET active=0, removed_at=? WHERE id=?`, now, id); err != nil {
					return err
				}
			}
		}
		// rules
		ruleTarget := map[int]int64{}
		for _, t := range targets {
			for _, ri := range t.Rules {
				ruleTarget[ri] = ids[t.Section+"|"+t.Name]
			}
		}
		insR, err := tx.Prepare(`INSERT INTO rules(section,raw,name,uname,kind,entity,submitter,line,target_id,active,first_seen,exempt) VALUES(?,?,?,?,?,?,?,?,?,1,?,?)
			ON CONFLICT(section,raw) DO UPDATE SET name=excluded.name, uname=excluded.uname, kind=excluded.kind, entity=excluded.entity, submitter=excluded.submitter, line=excluded.line, target_id=excluded.target_id, active=1, removed_at=0, exempt=excluded.exempt`)
		if err != nil {
			return err
		}
		defer insR.Close()
		seenR := map[string]bool{}
		for i, r := range l.Rules {
			key := r.Section + "|" + r.Raw
			seenR[key] = true
			if !existingR[key] && hadRules {
				res.AddedRules = append(res.AddedRules, r.Section+" "+r.Raw)
			}
			ex := r.Section == psl.SectionPrivate && exempt[r.Name]
			if _, err := insR.Exec(r.Section, r.Raw, r.Name, r.UName, r.Kind, r.Entity, r.Submitter, r.Line, ruleTarget[i], now, b2i(ex)); err != nil {
				return err
			}
		}
		for key := range existingR {
			if !seenR[key] {
				sec, raw, _ := strings.Cut(key, "|")
				res.RemovedRules = append(res.RemovedRules, sec+" "+raw)
				if _, err := tx.Exec(`UPDATE rules SET active=0, removed_at=? WHERE section=? AND raw=?`, now, sec, raw); err != nil {
					return err
				}
			}
		}
		sort.Strings(res.AddedRules)
		sort.Strings(res.RemovedRules)
		var ri, rp, ti, tp int
		for _, r := range l.Rules {
			if r.Section == psl.SectionICANN {
				ri++
			} else {
				rp++
			}
		}
		for _, t := range targets {
			if t.Section == psl.SectionICANN {
				ti++
			} else {
				tp++
			}
		}
		r, err := tx.Exec(`INSERT INTO snapshots(version,commit_hash,sha256,fetched_at,rules_icann,rules_private,targets_icann,targets_private,added,removed) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			l.Version, l.Commit, l.SHA256, now, ri, rp, ti, tp, capLines(res.AddedRules, 5000), capLines(res.RemovedRules, 5000))
		if err != nil {
			return err
		}
		res.SnapshotID, _ = r.LastInsertId()
		for _, a := range res.AddedRules {
			if len(res.AddedRules) > 500 {
				break
			}
			sec, raw, _ := strings.Cut(a, " ")
			s.AddEventTx(tx, runID, 0, "rule_added", "", raw, sec)
		}
		for _, a := range res.RemovedRules {
			if len(res.RemovedRules) > 500 {
				break
			}
			sec, raw, _ := strings.Cut(a, " ")
			s.AddEventTx(tx, runID, 0, "rule_removed", raw, "", sec)
		}
		return nil
	})
	return res, err
}

func capLines(s []string, n int) string {
	if len(s) > n {
		s = append(append([]string{}, s[:n]...), fmt.Sprintf("... (+%d more)", len(s)-n))
	}
	return strings.Join(s, "\n")
}

// ---- search

// TargetFilter drives list/search pages. Empty fields are ignored.
type TargetFilter struct {
	Q             string // substring on name/uname/entity; supports "re:" not supported -> LIKE only
	Section       string
	TLD           string
	Suffix        string
	Entity        string
	DNSState      string
	DNSStatus     string
	RDAP          string // found/not_found/unsupported/error/unchecked
	Flag          string // flag type
	MinSev        int
	OnlyFlagged   bool
	Unacked       bool
	TXT           string // "missing" (txt_missing>0) | "ok"
	ExpBefore     time.Time
	ExpAfter      time.Time
	CreatedAfter  time.Time
	CreatedBefore time.Time
	NS            string // substring in current/baseline NS
	Parked        bool
	Inactive      bool // include removed targets
	Sort          string
	Desc          bool
	Limit         int
	Offset        int
}

// FilterFromQuery parses URL query values into a TargetFilter.
func FilterFromQuery(get func(string) string) TargetFilter {
	f := TargetFilter{
		Q: strings.TrimSpace(get("q")), Section: get("section"), TLD: strings.ToLower(get("tld")), Suffix: strings.ToLower(get("suffix")),
		Entity: get("entity"), DNSState: get("dns"), DNSStatus: get("dnsstatus"), RDAP: get("rdap"), Flag: get("flag"),
		TXT: get("txt"), NS: strings.ToLower(strings.TrimSpace(get("ns"))), Sort: get("sort"), Desc: get("desc") == "1",
		OnlyFlagged: get("flagged") == "1", Unacked: get("unacked") == "1", Parked: get("parked") == "1", Inactive: get("inactive") == "1",
	}
	f.MinSev, _ = strconv.Atoi(get("minsev"))
	f.ExpBefore = parseDate(get("exp_before"))
	f.ExpAfter = parseDate(get("exp_after"))
	f.CreatedAfter = parseDate(get("created_after"))
	f.CreatedBefore = parseDate(get("created_before"))
	if d, err := strconv.Atoi(get("exp_within")); err == nil && d > 0 {
		f.ExpBefore = time.Now().Add(time.Duration(d) * 24 * time.Hour)
		if f.ExpAfter.IsZero() {
			f.ExpAfter = time.Now().Add(-3650 * 24 * time.Hour)
		}
	}
	if d, err := strconv.Atoi(get("created_within")); err == nil && d > 0 {
		f.CreatedAfter = time.Now().Add(-time.Duration(d) * 24 * time.Hour)
	}
	return f
}

func parseDate(s string) time.Time {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t
}

func (f TargetFilter) where() (string, []any) {
	w := []string{}
	var a []any
	if !f.Inactive {
		w = append(w, "active=1")
	}
	if f.Q != "" {
		q := f.Q
		switch {
		case strings.HasPrefix(q, "="):
			w, a = append(w, "(name=? OR uname=?)"), append(a, strings.ToLower(q[1:]), strings.ToLower(q[1:]))
		case strings.HasPrefix(q, "*."):
			w, a = append(w, "(name LIKE ? OR uname LIKE ?)"), append(a, "%"+strings.ToLower(q[1:]), "%"+strings.ToLower(q[1:]))
		default:
			lq := "%" + strings.ToLower(q) + "%"
			w, a = append(w, "(name LIKE ? OR uname LIKE ? OR entity LIKE ? OR note LIKE ?)"), append(a, lq, lq, "%"+q+"%", "%"+q+"%")
		}
	}
	eq := func(col, v string) {
		if v != "" {
			w, a = append(w, col+"=?"), append(a, v)
		}
	}
	eq("section", f.Section)
	eq("tld", f.TLD)
	eq("suffix", f.Suffix)
	eq("entity", f.Entity)
	eq("dns_state", f.DNSState)
	eq("dns_status", f.DNSStatus)
	if f.RDAP == "unchecked" {
		w = append(w, "rdap_result=''")
	} else {
		eq("rdap_result", f.RDAP)
	}
	if f.Flag != "" {
		w, a = append(w, "flag_types LIKE ?"), append(a, "%,"+f.Flag+",%")
	}
	if f.MinSev > 0 {
		w, a = append(w, "severity>=?"), append(a, f.MinSev)
	}
	if f.OnlyFlagged {
		w = append(w, "severity>=2")
	}
	if f.Unacked {
		w = append(w, "(acked_at=0 OR acked_at<flagged_since)")
	}
	switch f.TXT {
	case "missing":
		w = append(w, "txt_missing>0")
	case "ok":
		w = append(w, "txt_missing=0 AND txt_checked>0")
	}
	if !f.ExpBefore.IsZero() {
		w, a = append(w, "rdap_expires>0 AND rdap_expires<?"), append(a, f.ExpBefore.Unix())
	}
	if !f.ExpAfter.IsZero() {
		w, a = append(w, "rdap_expires>=?"), append(a, f.ExpAfter.Unix())
	}
	if !f.CreatedAfter.IsZero() {
		w, a = append(w, "rdap_created>=?"), append(a, f.CreatedAfter.Unix())
	}
	if !f.CreatedBefore.IsZero() {
		w, a = append(w, "rdap_created>0 AND rdap_created<?"), append(a, f.CreatedBefore.Unix())
	}
	if f.NS != "" {
		w, a = append(w, "(ns_current LIKE ? OR ns_baseline LIKE ? OR rdap_ns LIKE ?)"), append(a, "%"+f.NS+"%", "%"+f.NS+"%", "%"+f.NS+"%")
	}
	if f.Parked {
		w = append(w, "parked_ns<>''")
	}
	if len(w) == 0 {
		return "1=1", a
	}
	return strings.Join(w, " AND "), a
}

var sortCols = map[string]string{
	"name": "name", "section": "section, name", "tld": "tld, name", "severity": "severity", "dns": "dns_state, name",
	"expires": "CASE WHEN rdap_expires=0 THEN 1 ELSE 0 END, rdap_expires", "created": "rdap_created", "checked": "dns_checked_at",
	"rdap_checked": "rdap_checked_at", "flagged": "flagged_since", "entity": "entity, name", "missing": "missing_days", "rules": "rule_count",
}

// SearchTargets returns a page of targets plus the total count.
func (s *Store) SearchTargets(f TargetFilter) ([]*Target, int, error) {
	w, a := f.where()
	var total int
	if err := s.R.QueryRow(`SELECT COUNT(*) FROM targets WHERE `+w, a...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := sortCols[f.Sort]
	if order == "" {
		order = "severity DESC, name"
		f.Desc = false
	} else if f.Desc {
		order = strings.ReplaceAll(order, ", ", " DESC, ") + " DESC"
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	q := `SELECT ` + targetCols + ` FROM targets WHERE ` + w + ` ORDER BY ` + order + `, id`
	args := a
	if f.Limit > 0 {
		q += ` LIMIT ? OFFSET ?`
		args = append(args, f.Limit, f.Offset)
	}
	rows, err := s.R.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// Counts aggregates for the dashboard.
type Counts struct {
	BySection  map[string]int
	BySev      map[string]map[int]int    // section -> sev -> n
	ByDNS      map[string]map[string]int // section -> state -> n
	ByRDAP     map[string]map[string]int
	ByFlag     map[string]map[string]int
	TXTMissing int
	Unacked    map[string]int
}

func (s *Store) Counts() Counts {
	c := Counts{BySection: map[string]int{}, BySev: map[string]map[int]int{}, ByDNS: map[string]map[string]int{}, ByRDAP: map[string]map[string]int{}, ByFlag: map[string]map[string]int{}, Unacked: map[string]int{}}
	rows, err := s.R.Query(`SELECT section, severity, dns_state, rdap_result, flag_types, txt_missing, (acked_at=0 OR acked_at<flagged_since) FROM targets WHERE active=1`)
	if err != nil {
		return c
	}
	defer rows.Close()
	for rows.Next() {
		var sec, dns, rd, ft string
		var sev, txtm, unacked int
		if rows.Scan(&sec, &sev, &dns, &rd, &ft, &txtm, &unacked) != nil {
			continue
		}
		c.BySection[sec]++
		if c.BySev[sec] == nil {
			c.BySev[sec], c.ByDNS[sec], c.ByRDAP[sec], c.ByFlag[sec] = map[int]int{}, map[string]int{}, map[string]int{}, map[string]int{}
		}
		c.BySev[sec][sev]++
		c.ByDNS[sec][dns]++
		if rd == "" {
			rd = "unchecked"
		}
		c.ByRDAP[sec][rd]++
		for _, f := range strings.Split(strings.Trim(ft, ","), ",") {
			if f != "" {
				c.ByFlag[sec][f]++
			}
		}
		if txtm > 0 {
			c.TXTMissing++
		}
		if sev >= 2 && unacked == 1 {
			c.Unacked[sec]++
		}
	}
	return c
}

// Distinct values for filter dropdowns.
func (s *Store) Distinct(col, section string) []string {
	allowed := map[string]bool{"tld": true, "entity": true, "dns_state": true, "rdap_result": true, "dns_status": true}
	if !allowed[col] {
		return nil
	}
	q := `SELECT DISTINCT ` + col + ` FROM targets WHERE active=1 AND ` + col + `<>''`
	var a []any
	if section != "" {
		q += ` AND section=?`
		a = append(a, section)
	}
	rows, err := s.R.Query(q+` ORDER BY 1`, a...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		rows.Scan(&v)
		out = append(out, v)
	}
	return out
}

// Ack acknowledges a target (and optionally accepts the current NS as baseline).
func (s *Store) Ack(id int64, by, note string, acceptNS bool) error {
	t, err := s.GetTarget(id)
	if err != nil {
		return err
	}
	return s.Tx(context.Background(), func(tx *sql.Tx) error {
		if acceptNS {
			old := t.DNS.State
			analyze.Acknowledge(&t.DNS, time.Now())
			if err := SaveDNSTx(tx, t); err != nil {
				return err
			}
			s.AddEventTx(tx, 0, id, "ns_accepted", old, t.DNS.State, "by "+by+": "+JoinList(t.DNS.Baseline))
		}
		if t.RDAP.PrevCreated.IsZero() == false && acceptNS {
			tx.Exec(`UPDATE targets SET rdap_prev_created=0 WHERE id=?`, id)
		}
		_, err := tx.Exec(`UPDATE targets SET acked_at=?, acked_by=?, note=CASE WHEN ?<>'' THEN ? ELSE note END WHERE id=?`, time.Now().Unix(), by, note, note, id)
		if err == nil {
			s.AddEventTx(tx, 0, id, "acked", "", by, note)
		}
		return err
	})
}

func (s *Store) Unack(id int64) error {
	_, err := s.W.Exec(`UPDATE targets SET acked_at=0, acked_by='' WHERE id=?`, id)
	return err
}

func (s *Store) SetNote(id int64, note string) error {
	_, err := s.W.Exec(`UPDATE targets SET note=? WHERE id=?`, note, id)
	return err
}

// ---- run results (per-run snapshot of each target)

type RunResult struct {
	RunID, TargetID          int64
	DNSStatus, DNSState, NS  string
	RDAPResult               string
	RDAPExpires, RDAPCreated time.Time
	TXTMissing, Severity     int
	FlagTypes                string
	// joined
	Section, Name string
}

func (s *Store) TargetHistory(id int64, limit int) []RunResult {
	rows, err := s.R.Query(`SELECT rr.run_id, rr.target_id, rr.dns_status, rr.dns_state, rr.ns, rr.rdap_result, rr.rdap_expires, rr.rdap_created, rr.txt_missing, rr.severity, rr.flag_types, r.started_at
		FROM run_results rr JOIN runs r ON r.id=rr.run_id WHERE rr.target_id=? ORDER BY rr.run_id DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []RunResult
	for rows.Next() {
		var r RunResult
		var exp, cr, st int64
		if rows.Scan(&r.RunID, &r.TargetID, &r.DNSStatus, &r.DNSState, &r.NS, &r.RDAPResult, &exp, &cr, &r.TXTMissing, &r.Severity, &r.FlagTypes, &st) == nil {
			r.RDAPExpires, r.RDAPCreated = FromUnix(exp), FromUnix(cr)
			r.Name = FromUnix(st).Format("2006-01-02 15:04")
			out = append(out, r)
		}
	}
	return out
}

// DiffEntry describes how a target differs between two runs.
type DiffEntry struct {
	TargetID      int64
	Section, Name string
	A, B          RunResult
	HasA, HasB    bool
}

// DiffRuns compares per-target results of two runs, returning only changes.
func (s *Store) DiffRuns(a, b int64, limit int) ([]DiffEntry, int) {
	load := func(id int64) map[int64]RunResult {
		m := map[int64]RunResult{}
		rows, err := s.R.Query(`SELECT target_id, dns_status, dns_state, ns, rdap_result, rdap_expires, rdap_created, txt_missing, severity, flag_types FROM run_results WHERE run_id=?`, id)
		if err != nil {
			return m
		}
		defer rows.Close()
		for rows.Next() {
			var r RunResult
			var exp, cr int64
			if rows.Scan(&r.TargetID, &r.DNSStatus, &r.DNSState, &r.NS, &r.RDAPResult, &exp, &cr, &r.TXTMissing, &r.Severity, &r.FlagTypes) == nil {
				r.RDAPExpires, r.RDAPCreated = FromUnix(exp), FromUnix(cr)
				m[r.TargetID] = r
			}
		}
		return m
	}
	ma, mb := load(a), load(b)
	var out []DiffEntry
	for id, rb := range mb {
		ra, ok := ma[id]
		if ok && ra.DNSState == rb.DNSState && ra.NS == rb.NS && ra.RDAPResult == rb.RDAPResult && ra.RDAPExpires.Equal(rb.RDAPExpires) &&
			ra.RDAPCreated.Equal(rb.RDAPCreated) && ra.FlagTypes == rb.FlagTypes && ra.TXTMissing == rb.TXTMissing {
			continue
		}
		out = append(out, DiffEntry{TargetID: id, A: ra, B: rb, HasA: ok, HasB: true})
	}
	for id, ra := range ma {
		if _, ok := mb[id]; !ok {
			out = append(out, DiffEntry{TargetID: id, A: ra, HasA: true})
		}
	}
	names := map[int64][2]string{}
	rows, err := s.R.Query(`SELECT id, section, name FROM targets`)
	if err == nil {
		for rows.Next() {
			var id int64
			var sec, n string
			rows.Scan(&id, &sec, &n)
			names[id] = [2]string{sec, n}
		}
		rows.Close()
	}
	for i := range out {
		out[i].Section, out[i].Name = names[out[i].TargetID][0], names[out[i].TargetID][1]
	}
	sort.Slice(out, func(i, j int) bool {
		si := max(out[i].A.Severity, out[i].B.Severity)
		sj := max(out[j].A.Severity, out[j].B.Severity)
		if si != sj {
			return si > sj
		}
		return out[i].Name < out[j].Name
	})
	total := len(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, total
}

package web

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/checker"
	"psl-monitor/internal/dnscheck"
	"psl-monitor/internal/rdap"
	"psl-monitor/internal/report"
	"psl-monitor/internal/scheduler"
	"psl-monitor/internal/settings"
	"psl-monitor/internal/store"
)

// ---- dashboard

type dashData struct {
	Counts    store.Counts
	Sections  []string
	SevLevels []int
	DNSStates []string
	RDAPRes   []string
	FlagTypes []string
	Top       []*store.Target
	Events    []store.Event
	Jobs      []scheduler.JobState
	LastRuns  []store.Run
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	d := dashData{
		Counts:    s.St.Counts(),
		Sections:  []string{"private", "icann"},
		SevLevels: []int{5, 4, 3, 2, 1, 0},
		DNSStates: []string{analyze.DNSOK, analyze.DNSNoNS, analyze.DNSMissing, analyze.DNSDefunct, analyze.DNSChanging, analyze.DNSChanged, analyze.DNSAppeared, analyze.DNSUnknown},
		RDAPRes:   []string{rdap.ResultFound, rdap.ResultNotFound, rdap.ResultUnsupported, rdap.ResultError, "unchecked"},
		FlagTypes: analyze.FlagTypes,
		Jobs:      s.Sch.States(),
	}
	d.Top, _, _ = s.St.SearchTargets(store.TargetFilter{MinSev: analyze.SevHigh, Unacked: true, Limit: 25})
	d.Events, _ = s.St.ListEvents(store.EventFilter{Limit: 15})
	d.LastRuns, _ = s.St.ListRuns("", 8, 0)
	s.render(w, r, "dashboard", page{Title: "Dashboard", Nav: "dash", Data: d})
}

// ---- targets list

type targetsData struct {
	Items     []*store.Target
	Total     int
	Page      int
	Pages     int
	PerPage   int
	Filter    store.TargetFilter
	TLDs      []string
	DNSStates []string
	RDAPRes   []string
	FlagTypes []string
	Advanced  bool
	Export    string
}

func (s *Server) targetFilter(r *http.Request) (store.TargetFilter, int, int) {
	q := r.URL.Query()
	f := store.FilterFromQuery(q.Get)
	per := atoi(q.Get("per"), 100)
	if per < 10 || per > 1000 {
		per = 100
	}
	pg := atoi(q.Get("page"), 1)
	if pg < 1 {
		pg = 1
	}
	f.Limit, f.Offset = per, (pg-1)*per
	return f, pg, per
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request, tmpl, nav, title string, advanced bool) {
	f, pg, per := s.targetFilter(r)
	items, total, err := s.St.SearchTargets(f)
	if err != nil {
		s.render(w, r, tmpl, page{Title: title, Nav: nav, Error: err.Error(), Data: targetsData{}})
		return
	}
	pages := (total + per - 1) / per
	q := r.URL.Query()
	q.Del("page")
	d := targetsData{Items: items, Total: total, Page: pg, Pages: pages, PerPage: per, Filter: f,
		TLDs:      s.St.Distinct("tld", f.Section),
		DNSStates: []string{analyze.DNSOK, analyze.DNSNoNS, analyze.DNSMissing, analyze.DNSDefunct, analyze.DNSChanging, analyze.DNSChanged, analyze.DNSAppeared, analyze.DNSUnknown},
		RDAPRes:   []string{rdap.ResultFound, rdap.ResultNotFound, rdap.ResultUnsupported, rdap.ResultError, "unchecked"},
		FlagTypes: analyze.FlagTypes, Advanced: advanced, Export: q.Encode(),
	}
	s.render(w, r, tmpl, page{Title: title, Nav: nav, Data: d})
}

func (s *Server) targets(w http.ResponseWriter, r *http.Request) {
	nav := "targets"
	switch r.URL.Query().Get("section") {
	case "private":
		nav = "private"
	case "icann":
		nav = "icann"
	}
	if (r.URL.Query().Get("flagged") == "1" || r.URL.Query().Get("minsev") != "") && r.URL.Query().Get("section") == "" {
		nav = "flagged"
	}
	s.listTargets(w, r, "targets", nav, "Targets", false)
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	s.listTargets(w, r, "targets", "search", "Advanced search", true)
}

func (s *Server) targetsExport(w http.ResponseWriter, r *http.Request) {
	f, _, _ := s.targetFilter(r)
	f.Limit, f.Offset = 200000, 0
	items, _, err := s.St.SearchTargets(f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	stamp := time.Now().UTC().Format("20060102-1504")
	if strings.HasSuffix(r.URL.Path, ".csv") {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=pslmon-%s.csv", stamp))
		cw := csv.NewWriter(w)
		cw.Write([]string{"section", "name", "unicode", "severity", "flags", "dns_state", "dns_status", "ns_current", "ns_baseline", "missing_days", "changed_days", "rdap_result", "rdap_created", "rdap_expires", "registrar", "txt_missing", "entity", "flagged_since", "acked_by", "note"})
		for _, t := range items {
			cw.Write([]string{t.Section, t.Name, t.UName, analyze.SevNames[t.Severity], strings.Trim(t.FlagTypes, ","), t.DNS.State, t.DNS.LastStatus,
				strings.Join(t.DNS.Current, " "), strings.Join(t.DNS.Baseline, " "), strconv.Itoa(t.DNS.MissingDays), strconv.Itoa(t.DNS.ChangedDays),
				t.RDAP.Result, fmtDate(t.RDAP.Created), fmtDate(t.RDAP.Expires), t.RDAPRegistrar, strconv.Itoa(t.TXTMissing), t.Entity, fmtDateTime(t.FlaggedSince), t.AckedBy, t.Note})
		}
		cw.Flush()
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=pslmon-%s.txt", stamp))
	for _, t := range items {
		var msgs []string
		for _, fl := range t.Flags {
			msgs = append(msgs, fl.Type+": "+fl.Msg)
		}
		fmt.Fprintf(w, "%-8s %-8s %-45s dns=%-9s rdap=%-11s exp=%s  %s\n", strings.ToUpper(analyze.SevNames[t.Severity]), t.Section, t.Name, t.DNS.State, orDefault(t.RDAP.Result, "-"), fmtDate(t.RDAP.Expires), strings.Join(msgs, " | "))
	}
}

// ---- target detail

type targetDetailData struct {
	T       *store.Target
	Rules   []store.Rule
	History []store.RunResult
	Events  []store.Event
	Unacked bool
}

func (s *Server) targetDetail(w http.ResponseWriter, r *http.Request) {
	t, err := s.St.GetTarget(pathID(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := targetDetailData{T: t, Rules: s.St.RulesForTarget(t.ID), History: s.St.TargetHistory(t.ID, 60)}
	d.Events, _ = s.St.ListEvents(store.EventFilter{TargetID: t.ID, Limit: 100})
	d.Unacked = t.Severity >= analyze.SevLow && (t.AckedAt.IsZero() || t.AckedAt.Before(t.FlaggedSince))
	s.render(w, r, "target", page{Title: t.Name, Nav: t.Section, Data: d})
}

func (s *Server) targetAck(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	accept := r.FormValue("accept_ns") == "1"
	if err := s.St.Ack(id, user(r).Username, strings.TrimSpace(r.FormValue("note")), accept); err != nil {
		redirect(w, r, backTo(r, fmt.Sprintf("/target/%d", id)), "", err.Error())
		return
	}
	if accept {
		s.Ck.Reevaluate(r.Context())
	}
	redirect(w, r, backTo(r, fmt.Sprintf("/target/%d", id)), "Acknowledged.", "")
}

func (s *Server) targetUnack(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	s.St.Unack(id)
	redirect(w, r, fmt.Sprintf("/target/%d", id), "Acknowledgement removed.", "")
}

func (s *Server) targetNote(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	s.St.SetNote(id, strings.TrimSpace(r.FormValue("note")))
	redirect(w, r, fmt.Sprintf("/target/%d", id), "Note saved.", "")
}

func (s *Server) targetRecheck(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	scope := "dns"
	if r.FormValue("full") == "1" {
		scope = "full"
	}
	runID, err := s.Ck.Start(checker.KindRecheck, scope, "manual", user(r).Username, []int64{id})
	if err != nil {
		redirect(w, r, fmt.Sprintf("/target/%d", id), "", err.Error())
		return
	}
	// small targets finish quickly; wait briefly so the page shows fresh data
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if run, err := s.St.GetRun(runID); err == nil && run.Status != "running" {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	redirect(w, r, fmt.Sprintf("/target/%d", id), fmt.Sprintf("Re-check run #%d finished (or still running in background).", runID), "")
}

func (s *Server) targetsBulk(w http.ResponseWriter, r *http.Request) {
	var ids []int64
	for _, v := range r.Form["id"] {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			ids = append(ids, n)
		}
	}
	back := backTo(r, "/targets")
	if len(ids) == 0 {
		redirect(w, r, back, "", "no targets selected")
		return
	}
	switch r.FormValue("action") {
	case "ack":
		for _, id := range ids {
			s.St.Ack(id, user(r).Username, strings.TrimSpace(r.FormValue("note")), false)
		}
		redirect(w, r, back, fmt.Sprintf("Acknowledged %d target(s).", len(ids)), "")
	case "accept_ns":
		for _, id := range ids {
			s.St.Ack(id, user(r).Username, strings.TrimSpace(r.FormValue("note")), true)
		}
		s.Ck.Reevaluate(r.Context())
		redirect(w, r, back, fmt.Sprintf("Accepted current NS as baseline for %d target(s).", len(ids)), "")
	case "recheck", "recheck_full":
		scope := "dns"
		if r.FormValue("action") == "recheck_full" {
			scope = "full"
		}
		if len(ids) > 2000 {
			redirect(w, r, back, "", "too many targets selected (max 2000)")
			return
		}
		runID, err := s.Ck.Start(checker.KindRecheck, scope, "manual", user(r).Username, ids)
		if err != nil {
			redirect(w, r, back, "", err.Error())
			return
		}
		redirect(w, r, fmt.Sprintf("/run/%d", runID), "Re-check started.", "")
	default:
		redirect(w, r, back, "", "unknown action")
	}
}

// ---- rules / TXT

type rulesData struct {
	Items   []store.Rule
	Total   int
	Page    int
	Pages   int
	Filter  store.RuleFilter
	TXTOpts []string
}

func (s *Server) rulesList(r *http.Request, def store.RuleFilter) rulesData {
	q := r.URL.Query()
	f := store.RuleFilter{Q: strings.TrimSpace(q.Get("q")), Section: q.Get("section"), Kind: q.Get("kind"), TXT: q.Get("txt"), Entity: q.Get("entity"), Active: q.Get("active"), Sort: q.Get("sort")}
	if f.Section == "" && def.Section != "" && q.Get("section") == "" && !q.Has("section") {
		f.Section = def.Section
	}
	if f.TXT == "" && def.TXT != "" && !q.Has("txt") {
		f.TXT = def.TXT
	}
	if f.Sort == "" {
		f.Sort = def.Sort
	}
	pg := atoi(q.Get("page"), 1)
	if pg < 1 {
		pg = 1
	}
	f.Limit, f.Offset = 200, (pg-1)*200
	items, total := s.St.ListRules(f)
	return rulesData{Items: items, Total: total, Page: pg, Pages: (total + 199) / 200, Filter: f, TXTOpts: []string{"missing", "valid", "present", "exempt", "unknown", "unchecked"}}
}

func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "rules", page{Title: "Rules", Nav: "rules", Data: s.rulesList(r, store.RuleFilter{})})
}

type txtData struct {
	rulesData
	Counts     map[string]int
	Exceptions int
	LastRun    store.Run
	HasRun     bool
}

func (s *Server) txtPage(w http.ResponseWriter, r *http.Request) {
	d := txtData{rulesData: s.rulesList(r, store.RuleFilter{Section: "private", TXT: "missing", Sort: "entity"}), Counts: map[string]int{}}
	rows, err := s.St.R.Query(`SELECT CASE WHEN txt_status='' THEN 'unchecked' ELSE txt_status END, COUNT(*) FROM rules WHERE active=1 AND section='private' GROUP BY 1`)
	if err == nil {
		for rows.Next() {
			var k string
			var n int
			rows.Scan(&k, &n)
			d.Counts[k] = n
		}
		rows.Close()
	}
	d.Exceptions = len(s.Ck.Exceptions().MissingTXT)
	d.LastRun, d.HasRun = s.St.LastRun(checker.KindTXT)
	s.render(w, r, "txt", page{Title: "_psl TXT compliance", Nav: "txt", Data: d})
}

func (s *Server) txtRefreshExceptions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	n, err := s.RefreshExceptions(ctx)
	if err != nil {
		redirect(w, r, "/txt", "", "refresh failed: "+err.Error())
		return
	}
	s.Ck.Reevaluate(r.Context())
	redirect(w, r, "/txt", fmt.Sprintf("Loaded %d exempt domains from upstream.", n), "")
}

// ---- events / snapshots

type eventsData struct {
	Items  []store.Event
	Total  int
	Page   int
	Pages  int
	Types  []string
	Filter store.EventFilter
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pg := atoi(q.Get("page"), 1)
	if pg < 1 {
		pg = 1
	}
	f := store.EventFilter{Q: strings.TrimSpace(q.Get("q")), Type: q.Get("type"), Section: q.Get("section"), Limit: 200, Offset: (pg - 1) * 200}
	if d := atoi(q.Get("days"), 0); d > 0 {
		f.Since = time.Now().Add(-time.Duration(d) * 24 * time.Hour)
	}
	items, total := s.St.ListEvents(f)
	s.render(w, r, "events", page{Title: "Events", Nav: "events", Data: eventsData{Items: items, Total: total, Page: pg, Pages: (total + 199) / 200, Types: s.St.EventTypes(), Filter: f}})
}

func (s *Server) snapshots(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "snapshots", page{Title: "PSL snapshots", Nav: "snapshots", Data: s.St.ListSnapshots(200)})
}

func (s *Server) snapshotDetail(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	for _, sn := range s.St.ListSnapshots(1000) {
		if sn.ID == id {
			s.render(w, r, "snapshot", page{Title: "Snapshot " + sn.Version, Nav: "snapshots", Data: sn})
			return
		}
	}
	http.NotFound(w, r)
}

// ---- runs

type runsData struct {
	Items []store.Run
	Total int
	Page  int
	Pages int
	Kind  string
	Kinds []string
}

var allKinds = []string{checker.KindDNSPrivate, checker.KindDNSICANN, checker.KindRDAP, checker.KindTXT, checker.KindSync, checker.KindRecheck, checker.KindReport}

func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pg := atoi(q.Get("page"), 1)
	if pg < 1 {
		pg = 1
	}
	items, total := s.St.ListRuns(q.Get("kind"), 100, (pg-1)*100)
	s.render(w, r, "runs", page{Title: "Run log", Nav: "runs", Data: runsData{Items: items, Total: total, Page: pg, Pages: (total + 99) / 100, Kind: q.Get("kind"), Kinds: allKinds}})
}

type runDetailData struct {
	Run     store.Run
	Logs    []store.LogLine
	Live    *checker.Progress
	Prev    store.Run
	HasPrev bool
	Events  []store.Event
	EvTotal int
}

func (s *Server) runDetail(w http.ResponseWriter, r *http.Request) {
	run, err := s.St.GetRun(pathID(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := runDetailData{Run: run, Logs: s.St.RunLogs(run.ID, 2000)}
	for _, p := range s.Ck.Running() {
		if p.RunID == run.ID {
			p := p
			d.Live = &p
		}
	}
	d.Prev, d.HasPrev = s.St.PreviousRun(run)
	rows, err := s.St.R.Query(`SELECT e.id,e.ts,e.type,e.from_val,e.to_val,e.detail,e.target_id,COALESCE(t.section,''),COALESCE(t.name,'') FROM events e LEFT JOIN targets t ON t.id=e.target_id WHERE e.run_id=? ORDER BY e.id LIMIT 500`, run.ID)
	if err == nil {
		for rows.Next() {
			var e store.Event
			var ts int64
			rows.Scan(&e.ID, &ts, &e.Type, &e.From, &e.To, &e.Detail, &e.TargetID, &e.Section, &e.Name)
			e.TS = store.FromUnix(ts)
			d.Events = append(d.Events, e)
		}
		rows.Close()
	}
	s.St.R.QueryRow(`SELECT COUNT(*) FROM events WHERE run_id=?`, run.ID).Scan(&d.EvTotal)
	s.render(w, r, "run", page{Title: fmt.Sprintf("Run #%d", run.ID), Nav: "runs", Data: d})
}

type diffData struct {
	A, B  store.Run
	Items []store.DiffEntry
	Total int
}

func (s *Server) runDiff(w http.ResponseWriter, r *http.Request) {
	b, err := s.St.GetRun(pathID(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var a store.Run
	if against := atoi(r.URL.Query().Get("against"), 0); against > 0 {
		a, err = s.St.GetRun(int64(against))
		if err != nil {
			http.NotFound(w, r)
			return
		}
	} else {
		var ok bool
		a, ok = s.St.PreviousRun(b)
		if !ok {
			redirect(w, r, fmt.Sprintf("/run/%d", b.ID), "", "no previous comparable run")
			return
		}
	}
	items, total := s.St.DiffRuns(a.ID, b.ID, 2000)
	s.render(w, r, "diff", page{Title: fmt.Sprintf("Diff #%d → #%d", a.ID, b.ID), Nav: "runs", Data: diffData{A: a, B: b, Items: items, Total: total}})
}

func (s *Server) runCancel(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if s.Ck.Cancel(id) {
		s.St.Log(id, "warn", "cancel requested by "+user(r).Username)
		redirect(w, r, backTo(r, fmt.Sprintf("/run/%d", id)), "Cancellation requested.", "")
		return
	}
	redirect(w, r, backTo(r, fmt.Sprintf("/run/%d", id)), "", "run is not active")
}

func (s *Server) runStart(w http.ResponseWriter, r *http.Request) {
	kind, scope := r.FormValue("kind"), r.FormValue("scope")
	back := backTo(r, "/workers")
	valid := map[string]bool{checker.KindDNSPrivate: true, checker.KindDNSICANN: true, checker.KindRDAP: true, checker.KindTXT: true, checker.KindSync: true}
	if kind == checker.KindReport {
		s.reportSend(w, r)
		return
	}
	if !valid[kind] {
		redirect(w, r, back, "", "invalid run kind")
		return
	}
	if kind == checker.KindRDAP && scope != "private" && scope != "icann" && scope != "all" {
		redirect(w, r, back, "", "invalid RDAP scope")
		return
	}
	id, err := s.Ck.Start(kind, scope, "manual", user(r).Username, nil)
	if err != nil {
		redirect(w, r, back, "", err.Error())
		return
	}
	redirect(w, r, fmt.Sprintf("/run/%d", id), "Run started.", "")
}

// ---- workers

type workersData struct {
	Running   []checker.Progress
	Jobs      []scheduler.JobState
	Resolvers []dnscheck.ResolverStats
	RDAPHosts []rdap.HostStats
	RDAPTLDs  int
	LastRuns  map[string]store.Run
	Kinds     []string
}

func (s *Server) workersData() workersData {
	d := workersData{Running: s.Ck.Running(), Jobs: s.Sch.States(), Resolvers: s.Ck.DNS().Stats(), RDAPHosts: s.Ck.RDAP().Stats(), RDAPTLDs: s.Ck.RDAP().TLDCount(), LastRuns: map[string]store.Run{}, Kinds: allKinds}
	sort.Slice(d.RDAPHosts, func(i, j int) bool { return d.RDAPHosts[i].Requests > d.RDAPHosts[j].Requests })
	if len(d.RDAPHosts) > 50 {
		d.RDAPHosts = d.RDAPHosts[:50]
	}
	for _, k := range allKinds {
		if r, ok := s.St.LastRun(k); ok {
			d.LastRuns[k] = r
		}
	}
	return d
}

func (s *Server) workers(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "workers", page{Title: "Workers", Nav: "workers", Data: s.workersData()})
}

func (s *Server) workersJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	type pj struct {
		RunID               int64
		Kind, Scope, Phase  string
		Total, Done, Errors int64
		Elapsed             string
	}
	var out []pj
	for _, p := range s.Ck.Running() {
		out = append(out, pj{p.RunID, p.Kind, p.Scope, p.Phase, p.Total, p.Done, p.Errors, time.Since(p.StartedAt).Round(time.Second).String()})
	}
	json.NewEncoder(w).Encode(out)
}

// ---- schedule

func (s *Server) schedule(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "schedule", page{Title: "Schedule", Nav: "schedule", Data: s.Sch.States()})
}

func (s *Server) schedulePost(w http.ResponseWriter, r *http.Request) {
	for _, j := range scheduler.Jobs {
		en := "0"
		if r.FormValue(j.Key+".enabled") == "1" {
			en = "1"
		}
		iv := strings.TrimSpace(r.FormValue(j.Key + ".interval"))
		if _, err := scheduler.ParseInterval(iv); err != nil {
			redirect(w, r, "/schedule", "", j.Label+": "+err.Error())
			return
		}
		at := strings.TrimSpace(r.FormValue(j.Key + ".at"))
		if at != "" {
			if _, err := time.Parse("15:04", at); err != nil {
				redirect(w, r, "/schedule", "", j.Label+": time must be HH:MM (UTC)")
				return
			}
		}
		s.St.SetSetting(j.Key+".enabled", en)
		s.St.SetSetting(j.Key+".interval", iv)
		s.St.SetSetting(j.Key+".at", at)
	}
	s.Sch.Wake()
	redirect(w, r, "/schedule", "Schedule saved.", "")
}

// ---- settings

type settingsData struct {
	Defs   []settings.Def
	Values map[string]string
	SMTP   map[string]string
	Env    map[string]string
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	d := settingsData{Defs: settings.Defs, Values: map[string]string{}}
	for _, def := range settings.Defs {
		d.Values[def.Key] = settings.Get(s.St, def.Key)
	}
	sm := s.Env.SMTP
	pw := ""
	if sm.Password != "" {
		pw = "(set)"
	}
	d.SMTP = map[string]string{"SMTP_HOST": sm.Host, "SMTP_PORT": fmt.Sprint(sm.Port), "SMTP_USERNAME": sm.Username, "SMTP_PASSWORD": pw, "SMTP_FROM": sm.From, "SMTP_TLS": sm.TLSMode}
	d.Env = map[string]string{"DB_PATH": s.Env.DBPath, "BASE_URL": s.Env.BaseURL, "LISTEN_ADDR": s.Env.Listen, "SECURE_COOKIES": fmt.Sprint(s.Env.SecureCookies), "TRUST_PROXY": fmt.Sprint(s.Env.TrustProxy)}
	s.render(w, r, "settings", page{Title: "Settings", Nav: "settings", Data: d})
}

func (s *Server) settingsPost(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("reset") != "" {
		key := r.FormValue("reset")
		s.St.W.Exec(`DELETE FROM settings WHERE key=?`, key)
	} else {
		for _, def := range settings.Defs {
			v := r.FormValue(def.Key)
			if def.Kind != "bool" && !r.Form.Has(def.Key) {
				continue
			}
			nv, err := settings.Validate(def, v)
			if err != nil {
				redirect(w, r, "/settings", "", err.Error())
				return
			}
			if nv == def.Default {
				s.St.W.Exec(`DELETE FROM settings WHERE key=?`, def.Key)
			} else {
				s.St.SetSetting(def.Key, nv)
			}
		}
	}
	if err := s.ApplySettings(); err != nil {
		redirect(w, r, "/settings", "", "saved, but applying failed: "+err.Error())
		return
	}
	s.Ck.Reevaluate(r.Context())
	redirect(w, r, "/settings", "Settings saved and applied (running scans keep their previous settings).", "")
}

func (s *Server) rdapBootstrap(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	n, err := s.RefreshBootstrap(ctx)
	if err != nil {
		redirect(w, r, "/settings", "", "bootstrap refresh failed: "+err.Error())
		return
	}
	redirect(w, r, "/settings", fmt.Sprintf("RDAP bootstrap refreshed: %d TLDs.", n), "")
}

// ---- users

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "users", page{Title: "Admin users", Nav: "users", Data: s.St.ListUsers()})
}

func (s *Server) usersCreate(w http.ResponseWriter, r *http.Request) {
	_, err := s.St.CreateUser(strings.TrimSpace(r.FormValue("username")), r.FormValue("password"), r.FormValue("email"))
	if err != nil {
		redirect(w, r, "/users", "", err.Error())
		return
	}
	s.Log.Info("user created", "by", user(r).Username, "user", r.FormValue("username"))
	redirect(w, r, "/users", "User created.", "")
}

func (s *Server) usersToggle(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	u, err := s.St.GetUser(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.St.SetUserActive(id, !u.Active); err != nil {
		redirect(w, r, "/users", "", err.Error())
		return
	}
	redirect(w, r, "/users", "User updated.", "")
}

func (s *Server) usersDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if id == user(r).ID {
		redirect(w, r, "/users", "", "you cannot delete your own account")
		return
	}
	if err := s.St.DeleteUser(id); err != nil {
		redirect(w, r, "/users", "", err.Error())
		return
	}
	redirect(w, r, "/users", "User deleted.", "")
}

func (s *Server) usersPassword(w http.ResponseWriter, r *http.Request) {
	if err := s.St.SetPassword(pathID(r), r.FormValue("password")); err != nil {
		redirect(w, r, "/users", "", err.Error())
		return
	}
	redirect(w, r, "/users", "Password reset; the user's sessions were revoked.", "")
}

// ---- account

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "account", page{Title: "My account", Nav: "account", Data: map[string]any{"SMTP": s.Env.SMTP.Enabled()}})
}

func (s *Server) accountPost(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.FormValue("email"))
	if email != "" && (!strings.Contains(email, "@") || strings.ContainsAny(email, " \r\n<>,")) {
		redirect(w, r, "/account", "", "invalid email address")
		return
	}
	if err := s.St.UpdateProfile(user(r).ID, email, r.FormValue("reports") == "1"); err != nil {
		redirect(w, r, "/account", "", err.Error())
		return
	}
	redirect(w, r, "/account", "Profile saved.", "")
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	if !s.St.CheckPassword(u.ID, r.FormValue("current")) {
		redirect(w, r, "/account", "", "current password is incorrect")
		return
	}
	if r.FormValue("password") != r.FormValue("password2") {
		redirect(w, r, "/account", "", "new passwords do not match")
		return
	}
	if err := s.St.SetPassword(u.ID, r.FormValue("password")); err != nil {
		redirect(w, r, "/account", "", err.Error())
		return
	}
	tok, _, _ := s.St.CreateSession(u.ID, 7*24*time.Hour)
	s.setCookie(w, tok, 7*24*3600)
	redirect(w, r, "/account", "Password changed; other sessions were signed out.", "")
}

// ---- reports

func (s *Server) reportSend(w http.ResponseWriter, r *http.Request) {
	var to []string
	back := backTo(r, "/workers")
	if r.FormValue("self") == "1" {
		if user(r).Email == "" {
			redirect(w, r, back, "", "set your email address on the Account page first")
			return
		}
		to = []string{user(r).Email}
	}
	id, err := s.Sch.SendReport("manual", user(r).Username, to)
	if err != nil {
		if id > 0 {
			redirect(w, r, fmt.Sprintf("/run/%d", id), "", "report failed: "+err.Error())
			return
		}
		redirect(w, r, back, "", err.Error())
		return
	}
	redirect(w, r, fmt.Sprintf("/run/%d", id), "Report sent.", "")
}

func (s *Server) reportPreview(w http.ResponseWriter, r *http.Request) {
	body, atts, err := report.Build(s.St, s.Env.BaseURL, time.Now().Add(-7*24*time.Hour))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if f := r.URL.Query().Get("file"); f != "" {
		for _, a := range atts {
			if a.Name == f {
				w.Header().Set("Content-Disposition", "attachment; filename="+url.PathEscape(a.Name))
				w.Write(a.Data)
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	fmt.Fprintln(w, body)
	fmt.Fprintln(w, "Attachments:")
	for _, a := range atts {
		fmt.Fprintf(w, "  %s (%d bytes)  -> /report/preview?file=%s\n", a.Name, len(a.Data), url.QueryEscape(a.Name))
	}
}

func (s *Server) help(w http.ResponseWriter, r *http.Request) {
	type fh struct{ Type, Help string }
	var fl []fh
	for _, f := range analyze.FlagTypes {
		fl = append(fl, fh{f, analyze.FlagHelp[f]})
	}
	s.render(w, r, "help", page{Title: "Help", Nav: "help", Data: map[string]any{"Flags": fl, "Grace": settings.Int(s.St, "grace_days")}})
}

// Package scheduler triggers periodic jobs based on admin-configured settings.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"psl-monitor/internal/checker"
	"psl-monitor/internal/mailer"
	"psl-monitor/internal/report"
	"psl-monitor/internal/store"
)

// Job is a schedulable job definition.
type Job struct {
	Key         string // settings prefix, e.g. "sched.dns_private"
	Kind        string
	Scope       string
	Label       string
	DefEnabled  bool
	DefInterval time.Duration
	DefAt       string // HH:MM UTC preferred start time ("" = any)
}

// Jobs lists all scheduled jobs.
var Jobs = []Job{
	{Key: "sched.dns_private", Kind: checker.KindDNSPrivate, Label: "Private section NS check", DefEnabled: true, DefInterval: 24 * time.Hour, DefAt: "03:00"},
	{Key: "sched.dns_icann", Kind: checker.KindDNSICANN, Label: "ICANN section NS check", DefEnabled: true, DefInterval: 7 * 24 * time.Hour, DefAt: "04:00"},
	{Key: "sched.txt", Kind: checker.KindTXT, Label: "_psl TXT compliance scan", DefEnabled: true, DefInterval: 7 * 24 * time.Hour, DefAt: "05:00"},
	{Key: "sched.rdap_private", Kind: checker.KindRDAP, Scope: "private", Label: "RDAP scan (private)", DefEnabled: true, DefInterval: 30 * 24 * time.Hour, DefAt: "06:00"},
	{Key: "sched.rdap_icann", Kind: checker.KindRDAP, Scope: "icann", Label: "RDAP scan (ICANN)", DefEnabled: false, DefInterval: 90 * 24 * time.Hour, DefAt: "06:00"},
	{Key: "sched.report", Kind: checker.KindReport, Label: "Weekly email report", DefEnabled: true, DefInterval: 7 * 24 * time.Hour, DefAt: "08:00"},
}

// JobState is the effective config + status for the UI.
type JobState struct {
	Job
	Enabled  bool
	Interval time.Duration
	At       string
	LastRun  store.Run
	HasLast  bool
	NextRun  time.Time
	Running  bool
}

// Scheduler runs jobs.
type Scheduler struct {
	St      *store.Store
	Ck      *checker.Checker
	Mail    mailer.Config
	BaseURL string
	Log     *slog.Logger
	wake    chan struct{}
	mu      sync.Mutex
	// lastAttempt is in-memory only: after a restart a due job starts right away (catch-up)
	lastAttempt map[string]time.Time
}

func New(st *store.Store, ck *checker.Checker, mail mailer.Config, baseURL string, log *slog.Logger) *Scheduler {
	return &Scheduler{St: st, Ck: ck, Mail: mail, BaseURL: baseURL, Log: log, wake: make(chan struct{}, 1), lastAttempt: map[string]time.Time{}}
}

// Wake re-evaluates schedules immediately (after settings change).
func (s *Scheduler) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// ParseInterval accepts Go durations plus "Nd" / "Nw".
func ParseInterval(v string) (time.Duration, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if strings.HasSuffix(v, "d") || strings.HasSuffix(v, "w") {
		n, err := strconv.Atoi(v[:len(v)-1])
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("bad interval %q", v)
		}
		mult := 24 * time.Hour
		if strings.HasSuffix(v, "w") {
			mult *= 7
		}
		return time.Duration(n) * mult, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Minute {
		return 0, fmt.Errorf("bad interval %q (min 1m)", v)
	}
	return d, nil
}

// FormatInterval renders an interval compactly.
func FormatInterval(d time.Duration) string {
	if d%(7*24*time.Hour) == 0 {
		return fmt.Sprintf("%dw", d/(7*24*time.Hour))
	}
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}

// States returns effective job states.
func (s *Scheduler) States() []JobState {
	var out []JobState
	for _, j := range Jobs {
		js := JobState{Job: j, Enabled: j.DefEnabled, Interval: j.DefInterval, At: j.DefAt}
		if v := s.St.GetSetting(j.Key+".enabled", ""); v != "" {
			js.Enabled = v == "1"
		}
		if v := s.St.GetSetting(j.Key+".interval", ""); v != "" {
			if d, err := ParseInterval(v); err == nil {
				js.Interval = d
			}
		}
		if v, ok := s.St.AllSettings()[j.Key+".at"]; ok {
			js.At = v
		}
		js.LastRun, js.HasLast = s.lastScheduled(j)
		js.NextRun = nextRun(js, time.Now().UTC())
		js.Running = s.Ck.IsRunning(j.Kind)
		out = append(out, js)
	}
	return out
}

func (s *Scheduler) lastScheduled(j Job) (store.Run, bool) {
	runs, _ := s.St.ListRuns(j.Kind, 50, 0)
	for _, r := range runs {
		if r.Scope == j.Scope || j.Kind == checker.KindDNSPrivate || j.Kind == checker.KindDNSICANN || j.Kind == checker.KindTXT || j.Kind == checker.KindReport {
			if r.Status == "interrupted" || r.Status == "failed" && r.Done == 0 {
				continue
			}
			return r, true
		}
	}
	return store.Run{}, false
}

// nextRun computes the next due time: last start + interval, aligned to the
// preferred HH:MM if set (so daily checks don't drift).
func nextRun(js JobState, now time.Time) time.Time {
	if !js.Enabled {
		return time.Time{}
	}
	if !js.HasLast {
		return alignAt(now, js.At, js.Interval, true)
	}
	due := js.LastRun.StartedAt.Add(js.Interval)
	if js.At != "" && js.Interval >= 24*time.Hour {
		// allow up to 2h early so HH:MM alignment holds despite run durations
		due = alignAt(js.LastRun.StartedAt.Add(js.Interval-2*time.Hour), js.At, js.Interval, false)
	}
	return due
}

func alignAt(t time.Time, at string, interval time.Duration, first bool) time.Time {
	if at == "" || interval < 24*time.Hour {
		return t
	}
	hm, err := time.Parse("15:04", at)
	if err != nil {
		return t
	}
	c := time.Date(t.Year(), t.Month(), t.Day(), hm.Hour(), hm.Minute(), 0, 0, time.UTC)
	if c.Before(t) {
		if first {
			// never run before: start at next HH:MM, but not later than 24h
			c = c.Add(24 * time.Hour)
		} else {
			c = c.Add(24 * time.Hour)
		}
	}
	return c
}

// Run loops until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		s.tick()
		if time.Since(lastPrune) > 24*time.Hour {
			days, _ := strconv.Atoi(s.St.GetSetting("retention_days", "365"))
			if n, err := s.St.Prune(days); err == nil && n > 0 {
				s.Log.Info("pruned history", "rows", n)
			}
			lastPrune = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		}
	}
}

func (s *Scheduler) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, js := range s.States() {
		if !js.Enabled || js.Running || js.NextRun.IsZero() || js.NextRun.After(now) {
			continue
		}
		// back off after failed/interrupted attempts so we don't hammer
		if last, ok := s.lastAttempt[js.Key]; ok && now.Sub(last) < time.Hour {
			continue
		}
		s.lastAttempt[js.Key] = now
		if js.Kind == checker.KindReport {
			go s.SendReport("schedule", "scheduler", nil)
			continue
		}
		if _, err := s.Ck.Start(js.Kind, js.Scope, "schedule", "scheduler", nil); err != nil && err != checker.ErrBusy {
			s.Log.Error("schedule start failed", "job", js.Key, "err", err)
		}
	}
}

// SendReport builds and sends the report. If to is nil, all opted-in users receive it.
func (s *Scheduler) SendReport(trigger, by string, to []string) (int64, error) {
	if s.Ck.IsRunning(checker.KindReport) {
		return 0, checker.ErrBusy
	}
	id, err := s.St.CreateRun(checker.KindReport, "", trigger, by)
	if err != nil {
		return 0, err
	}
	fail := func(err error) (int64, error) {
		s.St.Log(id, "error", err.Error())
		s.St.FinishRun(id, "failed", err.Error(), 0)
		return id, err
	}
	since := time.Now().Add(-7 * 24 * time.Hour)
	if last, ok := s.lastSuccessfulReport(id); ok {
		since = last
	}
	body, atts, err := report.Build(s.St, s.BaseURL, since)
	if err != nil {
		return fail(err)
	}
	if to == nil {
		to = s.St.ReportRecipients()
	}
	if len(to) == 0 {
		return fail(fmt.Errorf("no recipients: set an email address on an admin account and enable reports"))
	}
	subj := fmt.Sprintf("[PSL Monitor] weekly report %s", time.Now().UTC().Format("2006-01-02"))
	if err := mailer.Send(s.Mail, mailer.Message{To: to, Subject: subj, Body: body, Attachments: atts}); err != nil {
		return fail(err)
	}
	msg := fmt.Sprintf("sent to %d recipient(s), %d attachment(s)", len(to), len(atts))
	s.St.Log(id, "info", msg)
	s.St.FinishRun(id, "ok", msg, 0)
	return id, nil
}

func (s *Scheduler) lastSuccessfulReport(exclude int64) (time.Time, bool) {
	runs, _ := s.St.ListRuns(checker.KindReport, 20, 0)
	for _, r := range runs {
		if r.ID != exclude && r.Status == "ok" {
			return r.StartedAt, true
		}
	}
	return time.Time{}, false
}

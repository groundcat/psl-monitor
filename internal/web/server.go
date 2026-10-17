// Package web is the admin UI.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/checker"
	"psl-monitor/internal/config"
	"psl-monitor/internal/scheduler"
	"psl-monitor/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server holds web dependencies.
type Server struct {
	St   *store.Store
	Ck   *checker.Checker
	Sch  *scheduler.Scheduler
	Env  config.Env
	Log  *slog.Logger
	tmpl map[string]*template.Template
	// ApplySettings rebuilds runtime components after settings changed.
	ApplySettings func() error
	// RefreshExceptions downloads the exceptions list.
	RefreshExceptions func(ctx context.Context) (int, error)
	// RefreshBootstrap downloads the IANA RDAP bootstrap.
	RefreshBootstrap func(ctx context.Context) (int, error)

	loginMu   sync.Mutex
	loginFail map[string][]time.Time
}

type ctxKey int

const (
	keyUser ctxKey = iota
	keyCSRF
)

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"sev":       func(n int) string { return analyze.SevNames[n] },
		"date":      fmtDate,
		"datetime":  fmtDateTime,
		"ago":       ago,
		"until":     until,
		"join":      strings.Join,
		"trimc":     func(s string) string { return strings.Trim(s, ",") },
		"split":     func(s string) []string { return strings.Split(strings.Trim(s, ","), ",") },
		"kindLabel": func(k string) string { return orDefault(checker.KindLabels[k], k) },
		"flagHelp":  func(f string) string { return analyze.FlagHelp[f] },
		"pct": func(a, b int64) int64 {
			if b == 0 {
				return 0
			}
			return a * 100 / b
		},
		"add":   func(a, b int) int { return a + b },
		"sub":   func(a, b int) int { return a - b },
		"query": func(v url.Values, kv ...string) template.URL { return template.URL(withQuery(v, kv...)) },
		"days": func(t time.Time) int {
			if t.IsZero() {
				return 0
			}
			return int(time.Until(t).Hours() / 24)
		},
		"interval": scheduler.FormatInterval,
		"dur":      func(d time.Duration) string { return d.Round(time.Second).String() },
		"ms":       func(d time.Duration) int64 { return d.Milliseconds() },
		"isZero":   func(t time.Time) bool { return t.IsZero() },
		"seq": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i
			}
			return out
		},
		"hasFlag": func(ft, f string) bool { return strings.Contains(ft, ","+f+",") },
		"pg": func(page, pages int, q url.Values) map[string]any {
			return map[string]any{"Page": page, "Pages": pages, "Q": q}
		},
		// dict_targets builds the payload for the "targettable" partial.
		// q (url.Values or nil) enables sortable headers.
		"dict_targets": func(items []*store.Target, csrf string, sel bool, q any) map[string]any {
			m := map[string]any{"Items": items, "CSRF": csrf, "Select": sel}
			if v, ok := q.(url.Values); ok {
				m["Sort"] = func(col string) template.URL {
					desc := ""
					if v.Get("sort") == col && v.Get("desc") != "1" {
						desc = "1"
					}
					return template.URL(withQuery(v, "sort", col, "desc", desc, "page", ""))
				}
			}
			return m
		},
		"dict_start": func(csrf, kind, scope, desc string, last store.Run) map[string]any {
			return map[string]any{"CSRF": csrf, "Kind": kind, "Scope": scope, "Desc": desc, "Last": last}
		},
		"sevRow": func(n int) string {
			if n >= analyze.SevLow {
				return "row-" + analyze.SevNames[n]
			}
			return ""
		},
	}
	s.tmpl = map[string]*template.Template{}
	pages, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" || strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/_partials.html", p)
		if err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.tmpl[name] = t
	}
	return nil
}

// Handler builds the HTTP handler.
func (s *Server) Handler() (http.Handler, error) {
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.loginFail = map[string][]time.Time{}
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServer(http.FS(static)))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.St.R.PingContext(r.Context()); err != nil {
			http.Error(w, "db: "+err.Error(), 503)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupPost)

	auth := func(p string, h http.HandlerFunc) { mux.Handle(p, s.requireAuth(h)) }
	auth("POST /logout", s.logout)
	auth("GET /{$}", s.dashboard)
	auth("GET /targets", s.targets)
	auth("GET /targets.txt", s.targetsExport)
	auth("GET /targets.csv", s.targetsExport)
	auth("GET /target/{id}", s.targetDetail)
	auth("POST /target/{id}/ack", s.targetAck)
	auth("POST /target/{id}/unack", s.targetUnack)
	auth("POST /target/{id}/note", s.targetNote)
	auth("POST /target/{id}/recheck", s.targetRecheck)
	auth("POST /targets/bulk", s.targetsBulk)
	auth("GET /search", s.search)
	auth("GET /rules", s.rules)
	auth("GET /txt", s.txtPage)
	auth("POST /txt/refresh-exceptions", s.txtRefreshExceptions)
	auth("GET /events", s.events)
	auth("GET /snapshots", s.snapshots)
	auth("GET /snapshot/{id}", s.snapshotDetail)
	auth("GET /runs", s.runs)
	auth("GET /run/{id}", s.runDetail)
	auth("GET /run/{id}/diff", s.runDiff)
	auth("POST /run/{id}/cancel", s.runCancel)
	auth("POST /runs/start", s.runStart)
	auth("GET /workers", s.workers)
	auth("GET /workers.json", s.workersJSON)
	auth("GET /schedule", s.schedule)
	auth("POST /schedule", s.schedulePost)
	auth("GET /settings", s.settingsPage)
	auth("POST /settings", s.settingsPost)
	auth("POST /settings/rdap-bootstrap", s.rdapBootstrap)
	auth("GET /users", s.users)
	auth("POST /users", s.usersCreate)
	auth("POST /users/{id}/toggle", s.usersToggle)
	auth("POST /users/{id}/delete", s.usersDelete)
	auth("POST /users/{id}/password", s.usersPassword)
	auth("GET /account", s.account)
	auth("POST /account", s.accountPost)
	auth("POST /account/password", s.accountPassword)
	auth("POST /report/send", s.reportSend)
	auth("GET /report/preview", s.reportPreview)
	auth("GET /help", s.help)
	return s.secHeaders(s.recoverer(mux)), nil
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.Log.Error("http panic", "path", r.URL.Path, "panic", v)
				http.Error(w, "internal error", 500)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

const cookieName = "pslmon_session"

func (s *Server) requireAuth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.St.CountUsers() == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil {
			s.toLogin(w, r)
			return
		}
		u, csrf, err := s.St.Session(c.Value)
		if err != nil {
			s.toLogin(w, r)
			return
		}
		if r.Method == http.MethodPost {
			r.ParseMultipartForm(1 << 20)
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(csrf)) != 1 {
				http.Error(w, "invalid CSRF token; reload the page and retry", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), keyUser, u)
		ctx = context.WithValue(ctx, keyCSRF, csrf)
		h(w, r.WithContext(ctx))
	})
}

func (s *Server) toLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.RequestURI()
	if r.Method != http.MethodGet {
		next = "/"
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
}

func user(r *http.Request) *store.User {
	u, _ := r.Context().Value(keyUser).(*store.User)
	return u
}

// page is the common template payload.
type page struct {
	Title   string
	Nav     string
	User    *store.User
	CSRF    string
	Flash   string
	Error   string
	Running []checker.Progress
	Snap    store.Snapshot
	Q       url.Values
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	t, ok := s.tmpl[name]
	if !ok {
		http.Error(w, "template not found: "+name, 500)
		return
	}
	p.User = user(r)
	p.CSRF, _ = r.Context().Value(keyCSRF).(string)
	if p.User != nil {
		p.Running = s.Ck.Running()
		p.Snap, _ = s.St.LatestSnapshot()
	}
	if p.Q == nil {
		p.Q = r.URL.Query()
	}
	if p.Flash == "" {
		p.Flash = r.URL.Query().Get("flash")
	}
	if p.Error == "" {
		p.Error = r.URL.Query().Get("err")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := t.Execute(w, p); err != nil {
		s.Log.Error("render", "template", name, "err", err)
	}
}

func redirect(w http.ResponseWriter, r *http.Request, to, flash, errMsg string) {
	u, _ := url.Parse(to)
	q := u.Query()
	if flash != "" {
		q.Set("flash", flash)
	}
	if errMsg != "" {
		q.Set("err", errMsg)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func backTo(r *http.Request, def string) string {
	if b := r.FormValue("back"); strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
		return b
	}
	return def
}

// ---- login / setup

func (s *Server) clientIP(r *http.Request) string {
	if s.Env.TrustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			return strings.TrimSpace(strings.Split(xf, ",")[0])
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) throttled(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	var keep []time.Time
	for _, t := range s.loginFail[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.loginFail[ip] = keep
	return len(keep) >= 10
}

func (s *Server) noteFail(ip string) {
	s.loginMu.Lock()
	s.loginFail[ip] = append(s.loginFail[ip], time.Now())
	s.loginMu.Unlock()
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.St.CountUsers() == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", page{Title: "Login"})
}

func (s *Server) setCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.Env.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.throttled(ip) {
		s.render(w, r, "login", page{Title: "Login", Error: "Too many failed attempts. Try again in 15 minutes."})
		return
	}
	u, err := s.St.Authenticate(strings.TrimSpace(r.FormValue("username")), r.FormValue("password"))
	if err != nil {
		s.noteFail(ip)
		s.Log.Warn("login failed", "ip", ip, "user", r.FormValue("username"))
		s.render(w, r, "login", page{Title: "Login", Error: err.Error()})
		return
	}
	tok, _, err := s.St.CreateSession(u.ID, 7*24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.setCookie(w, tok, 7*24*3600)
	s.Log.Info("login", "user", u.Username, "ip", ip)
	next := r.URL.Query().Get("next")
	if next == "" {
		next = r.FormValue("next")
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.St.DeleteSession(c.Value)
	}
	s.setCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if s.St.CountUsers() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup", page{Title: "Initial setup"})
}

func (s *Server) setupPost(w http.ResponseWriter, r *http.Request) {
	if s.St.CountUsers() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.FormValue("password") != r.FormValue("password2") {
		s.render(w, r, "setup", page{Title: "Initial setup", Error: "passwords do not match"})
		return
	}
	id, err := s.St.CreateUser(strings.TrimSpace(r.FormValue("username")), r.FormValue("password"), r.FormValue("email"))
	if err != nil {
		s.render(w, r, "setup", page{Title: "Initial setup", Error: err.Error()})
		return
	}
	tok, _, _ := s.St.CreateSession(id, 7*24*time.Hour)
	s.setCookie(w, tok, 7*24*3600)
	redirect(w, r, "/", "Admin account created. Start with a DNS or RDAP run from the Workers page.", "")
}

// ---- helpers

func atoi(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func pathID(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return n
}

func withQuery(v url.Values, kv ...string) string {
	q := url.Values{}
	for k, vs := range v {
		q[k] = append([]string(nil), vs...)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			q.Del(kv[i])
		} else {
			q.Set(kv[i], kv[i+1])
		}
	}
	return "?" + q.Encode()
}

func fmtDate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02")
}

func fmtDateTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < 0:
		return "in " + until(t)
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func until(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Until(t)
	if d < 0 {
		return "due"
	}
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes())+1)
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

var errNotFound = errors.New("not found")

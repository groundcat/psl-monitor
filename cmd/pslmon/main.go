// Command pslmon is the PSL monitor server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/checker"
	"psl-monitor/internal/compliance"
	"psl-monitor/internal/config"
	"psl-monitor/internal/psl"
	"psl-monitor/internal/rdap"
	"psl-monitor/internal/scheduler"
	"psl-monitor/internal/settings"
	"psl-monitor/internal/store"
	"psl-monitor/internal/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "user" {
		userCmd(os.Args[2:])
		return
	}
	env := config.Load()
	level := slog.LevelInfo
	switch strings.ToLower(env.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	st, err := store.Open(env.DBPath)
	if err != nil {
		log.Error("open db", "path", env.DBPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()
	st.MarkInterruptedRuns()
	bootstrapAdmin(st, env, log)

	exc := compliance.Embedded()
	if src := st.GetSetting("exceptions_source", ""); src != "" {
		if e, err := compliance.Parse(src); err == nil {
			exc = e
		}
	}
	pool, err := settings.DNSPool(st)
	if err != nil {
		log.Warn("resolver settings invalid, using defaults", "err", err)
		st.W.Exec(`DELETE FROM settings WHERE key='resolvers'`)
		pool, _ = settings.DNSPool(st)
	}
	newRDAP := func() *rdap.Client {
		c := rdap.New(rdap.Options{PerHostConc: settings.Int(st, "rdap_host_conc"), PerHostQPS: float64(settings.Int(st, "rdap_host_qps")), Overrides: settings.Overrides(settings.Get(st, "rdap_overrides"))})
		if b := st.GetSetting("rdap_bootstrap", ""); b != "" {
			c.LoadBootstrap([]byte(b))
		}
		if b := st.GetSetting("rdap_extra", ""); b != "" {
			c.LoadExtra([]byte(b))
		}
		return c
	}
	park := analyze.NewParking(settings.Get(st, "parking_ns"), settings.Lines(settings.Get(st, "parking_keywords")))
	ck := checker.New(st, pool, newRDAP(), park, exc, settings.CheckerConfig(st), log)
	applyWhois := func() {
		w := settings.WhoisClient(st, env.WhoisURL, env.WhoisPassword)
		ck.SetWHOIS(w)
		if w == nil {
			if env.WhoisURL == "" {
				log.Info("whois fallback disabled (WHOIS_FALLBACK_URL not set)")
			} else {
				log.Info("whois fallback disabled in settings")
			}
			return
		}
		go func() {
			c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := w.Ping(c); err != nil {
				log.Warn("whois fallback service not reachable", "url", w.BaseURL(), "err", err)
				return
			}
			log.Info("whois fallback enabled", "url", w.BaseURL(), "upstream", w.Version(c))
			// community RDAP servers missing from IANA (e.g. .ch, .de, .co)
			if b, err := w.ExtraRDAPServers(c); err != nil {
				log.Warn("could not load extra RDAP servers from whois service", "err", err)
			} else if n, err := ck.RDAP().LoadExtra(b); err == nil {
				st.SetSetting("rdap_extra", string(b))
				log.Info("loaded extra RDAP servers from whois-domain-lookup", "count", n)
			}
		}()
	}
	applyWhois()
	sch := scheduler.New(st, ck, env.SMTP, env.BaseURL, log)

	refreshBootstrap := func(ctx context.Context) (int, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", rdap.BootstrapURL, nil)
		resp, err := psl.HTTPClient().Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		var b strings.Builder
		if _, err := ioCopy(&b, resp.Body, 4<<20); err != nil {
			return 0, err
		}
		if err := ck.RDAP().LoadBootstrap([]byte(b.String())); err != nil {
			return 0, err
		}
		st.SetSetting("rdap_bootstrap", b.String())
		return ck.RDAP().TLDCount(), nil
	}

	srv := &web.Server{St: st, Ck: ck, Sch: sch, Env: env, Log: log}
	srv.ApplySettings = func() error {
		p, err := settings.DNSPool(st)
		if err != nil {
			return err
		}
		ck.SetDNS(p)
		ck.SetRDAP(newRDAP())
		applyWhois()
		park.Load(settings.Get(st, "parking_ns"), settings.Lines(settings.Get(st, "parking_keywords")))
		ck.SetConfig(settings.CheckerConfig(st))
		sch.Wake()
		return nil
	}
	srv.RefreshExceptions = func(ctx context.Context) (int, error) {
		e, src, err := compliance.Fetch(psl.HTTPClient(), settings.Get(st, "exceptions_url"))
		if err != nil {
			return 0, err
		}
		ck.SetExceptions(e)
		st.SetSetting("exceptions_source", src)
		if err := st.RefreshExemptions(e.MissingTXT); err != nil {
			return 0, err
		}
		return len(e.MissingTXT), nil
	}
	srv.RefreshBootstrap = refreshBootstrap
	h, err := srv.Handler()
	if err != nil {
		log.Error("web init", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		// refresh RDAP bootstrap at startup and daily; failures fall back to the embedded copy
		for {
			c, cancel := context.WithTimeout(ctx, time.Minute)
			if n, err := refreshBootstrap(c); err != nil {
				log.Warn("rdap bootstrap refresh failed", "err", err)
			} else {
				log.Info("rdap bootstrap refreshed", "tlds", n)
			}
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-time.After(24 * time.Hour):
			}
		}
	}()
	go sch.Run(ctx)

	hs := &http.Server{Addr: env.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		log.Info("listening", "addr", env.Listen, "db", env.DBPath)
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	log.Info("shutting down")
	for _, p := range ck.Running() {
		ck.Cancel(p.RunID)
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	hs.Shutdown(sctx)
	// give cancelled runs a moment to flush their last batch
	deadline := time.Now().Add(10 * time.Second)
	for len(ck.Running()) > 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
}

func bootstrapAdmin(st *store.Store, env config.Env, log *slog.Logger) {
	if env.AdminUser == "" || env.AdminPassword == "" || st.CountUsers() > 0 {
		return
	}
	if _, err := st.CreateUser(env.AdminUser, env.AdminPassword, env.AdminEmail); err != nil {
		log.Error("bootstrap admin from env failed", "err", err)
		return
	}
	log.Info("created initial admin from environment", "user", env.AdminUser)
}

func healthcheck() {
	addr := config.Load().Listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		os.Exit(1)
	}
}

// userCmd: pslmon user reset-password <username> <password>  |  pslmon user create <username> <password> [email]
func userCmd(args []string) {
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	fs.Parse(args)
	a := fs.Args()
	env := config.Load()
	st, err := store.Open(env.DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer st.Close()
	switch {
	case len(a) >= 3 && a[0] == "create":
		email := ""
		if len(a) > 3 {
			email = a[3]
		}
		if _, err := st.CreateUser(a[1], a[2], email); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("created", a[1])
	case len(a) == 3 && a[0] == "reset-password":
		var id int64
		if err := st.R.QueryRow(`SELECT id FROM users WHERE username=?`, a[1]).Scan(&id); err != nil {
			fmt.Fprintln(os.Stderr, "no such user")
			os.Exit(1)
		}
		if err := st.SetPassword(id, a[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		st.SetUserActive(id, true)
		fmt.Println("password reset for", a[1])
	default:
		fmt.Fprintln(os.Stderr, "usage: pslmon user create <username> <password> [email]\n       pslmon user reset-password <username> <password>")
		os.Exit(2)
	}
}

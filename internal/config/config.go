// Package config loads process configuration from the environment.
package config

import (
	"os"
	"strconv"
	"strings"

	"psl-monitor/internal/mailer"
)

// Env is process-level configuration. Credentials live only here (from .env),
// never in the database.
type Env struct {
	Listen        string
	DBPath        string
	BaseURL       string
	SecureCookies bool
	TrustProxy    bool
	AdminUser     string
	AdminPassword string
	AdminEmail    string
	SMTP          mailer.Config
	LogLevel      string
	// WHOIS fallback service (reg233/whois-domain-lookup sidecar).
	WhoisURL      string
	WhoisPassword string
}

func get(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func getBool(k string, def bool) bool {
	v := strings.ToLower(get(k, ""))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// Load reads configuration from environment variables.
func Load() Env {
	port, _ := strconv.Atoi(get("SMTP_PORT", "0"))
	base := strings.TrimRight(get("BASE_URL", ""), "/")
	return Env{
		Listen:        get("LISTEN_ADDR", ":8080"),
		DBPath:        get("DB_PATH", "./data/pslmon.db"),
		BaseURL:       base,
		SecureCookies: getBool("SECURE_COOKIES", strings.HasPrefix(base, "https://")),
		TrustProxy:    getBool("TRUST_PROXY", false),
		AdminUser:     get("ADMIN_USERNAME", ""),
		AdminPassword: get("ADMIN_PASSWORD", ""),
		AdminEmail:    get("ADMIN_EMAIL", ""),
		LogLevel:      get("LOG_LEVEL", "info"),
		WhoisURL:      get("WHOIS_FALLBACK_URL", ""),
		WhoisPassword: get("WHOIS_FALLBACK_PASSWORD", ""),
		SMTP: mailer.Config{
			Host:               get("SMTP_HOST", ""),
			Port:               port,
			Username:           get("SMTP_USERNAME", ""),
			Password:           get("SMTP_PASSWORD", ""),
			From:               get("SMTP_FROM", ""),
			TLSMode:            get("SMTP_TLS", "starttls"),
			InsecureSkipVerify: getBool("SMTP_INSECURE_SKIP_VERIFY", false),
		},
	}
}

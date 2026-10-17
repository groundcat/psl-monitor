// Package mailer sends multipart email with attachments over SMTP.
package mailer

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Config comes from the environment.
type Config struct {
	Host               string
	Port               int
	Username           string
	Password           string
	From               string
	TLSMode            string // "starttls" (default), "tls" (implicit), "none"
	InsecureSkipVerify bool
}

func (c Config) Enabled() bool { return c.Host != "" && c.From != "" }

// Attachment is a file attached to a message.
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

// Message is an email.
type Message struct {
	To          []string
	Subject     string
	Body        string
	Attachments []Attachment
}

func boundary() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "pslmon-" + hex.EncodeToString(b)
}

func headerSafe(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// Build renders the RFC 5322 message.
func Build(from string, m Message) []byte {
	var b bytes.Buffer
	bd := boundary()
	fmt.Fprintf(&b, "From: %s\r\n", headerSafe(from))
	fmt.Fprintf(&b, "To: %s\r\n", headerSafe(strings.Join(m.To, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", headerSafe(m.Subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	host := "psl-monitor.local"
	if i := strings.LastIndexByte(from, '@'); i >= 0 {
		host = strings.Trim(from[i+1:], "> ")
	}
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", boundary(), host)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", bd)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n", bd)
	writeB64(&b, []byte(m.Body))
	for _, a := range m.Attachments {
		ct := a.ContentType
		if ct == "" {
			ct = "text/plain; charset=utf-8"
		}
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=%q\r\n\r\n", bd, ct, headerSafe(a.Name))
		writeB64(&b, a.Data)
	}
	fmt.Fprintf(&b, "--%s--\r\n", bd)
	return b.Bytes()
}

func writeB64(b *bytes.Buffer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n")
}

// Send delivers a message.
func Send(c Config, m Message) error {
	if !c.Enabled() {
		return errors.New("SMTP not configured (set SMTP_HOST and SMTP_FROM)")
	}
	if len(m.To) == 0 {
		return errors.New("no recipients")
	}
	port := c.Port
	mode := strings.ToLower(c.TLSMode)
	if port == 0 {
		switch mode {
		case "tls":
			port = 465
		case "none":
			port = 25
		default:
			port = 587
		}
	}
	addr := net.JoinHostPort(c.Host, fmt.Sprint(port))
	tlsCfg := &tls.Config{ServerName: c.Host, InsecureSkipVerify: c.InsecureSkipVerify}
	var conn net.Conn
	var err error
	d := &net.Dialer{Timeout: 20 * time.Second}
	if mode == "tls" {
		conn, err = tls.DialWithDialer(d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if mode != "tls" && mode != "none" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("server does not support STARTTLS (set SMTP_TLS=none to allow plaintext)")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	from := c.From
	if i := strings.IndexByte(from, '<'); i >= 0 {
		from = strings.Trim(from[i:], "<> ")
	}
	if err := cl.Mail(from); err != nil {
		return err
	}
	for _, to := range m.To {
		if err := cl.Rcpt(to); err != nil {
			return fmt.Errorf("rcpt %s: %w", to, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(Build(c.From, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

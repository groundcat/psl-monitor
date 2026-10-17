package mailer

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// fake SMTP server capturing one message
func fakeSMTP(t *testing.T) (string, chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
		say := func(s string) { rw.WriteString(s + "\r\n"); rw.Flush() }
		say("220 fake")
		var data strings.Builder
		inData := false
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					out <- data.String()
					say("250 ok")
					continue
				}
				data.WriteString(line)
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 fake")
			case cmd == "DATA":
				inData = true
				say("354 go")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), out
}

func TestSend(t *testing.T) {
	addr, out := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	var p int
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	cfg := Config{Host: host, Port: p, From: "PSL Monitor <mon@example.com>", TLSMode: "none"}
	err := Send(cfg, Message{To: []string{"a@example.com"}, Subject: "weekly ✓", Body: "hello", Attachments: []Attachment{{Name: "flagged.txt", Data: []byte("x.example\n")}}})
	if err != nil {
		t.Fatal(err)
	}
	msg := <-out
	for _, want := range []string{"Subject: =?utf-8?", "multipart/mixed", `filename="flagged.txt"`, "To: a@example.com"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in message", want)
		}
	}
	if err := Send(Config{}, Message{To: []string{"a@b"}}); err == nil {
		t.Fatal("unconfigured SMTP must error")
	}
}

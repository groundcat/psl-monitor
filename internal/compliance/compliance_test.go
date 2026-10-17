package compliance

import "testing"

func TestEmbedded(t *testing.T) {
	e := Embedded()
	if len(e.MissingTXT) < 600 {
		t.Fatalf("missingTXT=%d", len(e.MissingTXT))
	}
	if !e.MissingTXT["akamai.net"] || !e.MissingTXT["001www.com"] {
		t.Fatal("expected entries missing")
	}
	if e.AcceptPRs["js.org"] != 264 || e.ReplacePRs[596] != 652 {
		t.Fatalf("accept/replace parse: %v %v", e.AcceptPRs, e.ReplacePRs)
	}
}

func TestEvaluate(t *testing.T) {
	e := Embedded()
	if s, prs := e.Evaluate("x.example", true, true, []string{"https://github.com/publicsuffix/list/pull/1234"}); s != TXTValid || prs[0] != 1234 {
		t.Fatal(s)
	}
	if s, _ := e.Evaluate("x.example", true, true, []string{"hello"}); s != TXTPresent {
		t.Fatal(s)
	}
	if s, _ := e.Evaluate("akamai.net", false, true, nil); s != TXTExempt {
		t.Fatal(s)
	}
	if s, _ := e.Evaluate("x.example", false, true, nil); s != TXTMissing {
		t.Fatal(s)
	}
	if s, _ := e.Evaluate("x.example", false, false, nil); s != TXTUnknown {
		t.Fatal(s)
	}
}

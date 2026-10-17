package psl

import (
	"os"
	"strings"
	"testing"
)

const sample = `// header
// VERSION: 2026-10-16_09-29-46_UTC
// COMMIT: 91b4bd846240a84afb33695d5a51adcbc4cfd9ca

// ===BEGIN ICANN DOMAINS===

// pl : https://dns.pl
pl
edu.pl
com.pl

// jp
jp
*.kawasaki.jp
!city.kawasaki.jp

// ck
*.ck
!www.ck
// ===END ICANN DOMAINS===

// ===BEGIN PRIVATE DOMAINS===

// Foo Corp : https://foo.example
// Submitted by Foo <foo@example.com>
foo1.bar.edu.pl
foo2.bar.edu.pl
*.foo3.bar.edu.pl
baz.pl
app.city.kawasaki.jp
// ===END PRIVATE DOMAINS===
`

func pad(s string) string {
	// Parse refuses tiny lists; pad both sections with dummy rules.
	var icann, priv strings.Builder
	for i := 0; i < 120; i++ {
		icann.WriteString("x" + itoa(i) + ".pl\n")
		priv.WriteString("p" + itoa(i) + ".example.pl\n")
	}
	s = strings.Replace(s, "// ===END ICANN DOMAINS===", icann.String()+"// ===END ICANN DOMAINS===", 1)
	s = strings.Replace(s, "// ===END PRIVATE DOMAINS===", priv.String()+"// ===END PRIVATE DOMAINS===", 1)
	return s
}

func itoa(i int) string {
	return strings.TrimLeft(string([]byte{byte('0' + i/100), byte('0' + i/10%10), byte('0' + i%10)}), "0")
}

func TestParseSample(t *testing.T) {
	l, err := Parse([]byte(pad(sample)))
	if err != nil {
		t.Fatal(err)
	}
	if l.Version != "2026-10-16_09-29-46_UTC" || l.Commit != "91b4bd846240a84afb33695d5a51adcbc4cfd9ca" {
		t.Fatalf("version/commit: %q %q", l.Version, l.Commit)
	}
	m := l.ICANN()
	cases := map[string]string{
		"foo1.bar.edu.pl":       "bar.edu.pl",
		"x.foo3.bar.edu.pl":     "bar.edu.pl",
		"baz.pl":                "baz.pl",
		"app.city.kawasaki.jp":  "city.kawasaki.jp",
		"a.b.foo.kawasaki.jp":   "b.foo.kawasaki.jp",
		"www.ck":                "www.ck",
		"a.b.ck":                "a.b.ck",
		"something.unknowntld":  "something.unknowntld",
	}
	for in, want := range cases {
		if got, _ := m.Registrable(in); got != want {
			t.Errorf("Registrable(%s)=%s want %s", in, got, want)
		}
	}
	var priv []string
	for _, tg := range l.Targets() {
		if tg.Section == SectionPrivate && !strings.HasSuffix(tg.Name, "example.pl") {
			priv = append(priv, tg.Name)
		}
	}
	want := "bar.edu.pl,baz.pl,city.kawasaki.jp"
	if strings.Join(priv, ",") != want {
		t.Fatalf("private targets %v want %s", priv, want)
	}
	for _, r := range l.Rules {
		if r.Raw == "*.foo3.bar.edu.pl" {
			if r.Kind != KindWildcard || r.Name != "foo3.bar.edu.pl" || r.Entity != "Foo Corp" || r.Submitter != "Foo <foo@example.com>" {
				t.Fatalf("bad rule %+v", r)
			}
		}
	}
}

func TestParseReal(t *testing.T) {
	b, err := os.ReadFile("/tmp/opencode/psl.dat")
	if err != nil {
		t.Skip("no local PSL copy")
	}
	l, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	var ni, np int
	for _, tg := range l.Targets() {
		if tg.Section == SectionICANN {
			ni++
		} else {
			np++
		}
	}
	t.Logf("version=%s rules=%d icann targets=%d private targets=%d", l.Version, len(l.Rules), ni, np)
	if ni < 5000 || np < 1000 {
		t.Fatalf("unexpected target counts")
	}
}

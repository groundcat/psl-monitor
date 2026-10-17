// Package compliance handles the _psl TXT requirement for private entries.
package compliance

import (
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// DefaultExceptionsURL is the pinned upstream exceptions file.
const DefaultExceptionsURL = "https://raw.githubusercontent.com/publicsuffix/list/2dbfce14c57bcea83fef2be3bdcb560667d7ef93/tools/internal/parser/exceptions.go"

//go:embed exceptions.go.txt
var embeddedExceptions string

var (
	reMissingTXT = regexp.MustCompile(`(?s)var\s+missingTXT\s*=\s*mapset\.New\((.*?)\n\)`)
	reAcceptPRs  = regexp.MustCompile(`(?s)var\s+txtAcceptPRs\s*=\s*map\[string\]int\{(.*?)\n\}`)
	reReplacePRs = regexp.MustCompile(`(?s)var\s+txtReplacePRs\s*=\s*map\[int\]int\{(.*?)\n\}`)
	reQuoted     = regexp.MustCompile(`"([^"]+)"`)
	reKV         = regexp.MustCompile(`"([^"]+)"\s*:\s*(\d+)`)
	reIntKV      = regexp.MustCompile(`(\d+)\s*:\s*(\d+)`)
	rePR         = regexp.MustCompile(`(?i)github\.com/publicsuffix/list/pull/(\d+)`)
)

// Exceptions is the parsed upstream exceptions data.
type Exceptions struct {
	MissingTXT map[string]bool
	AcceptPRs  map[string]int
	ReplacePRs map[int]int
}

// Parse extracts exception sets from the Go source of exceptions.go.
func Parse(src string) (*Exceptions, error) {
	e := &Exceptions{MissingTXT: map[string]bool{}, AcceptPRs: map[string]int{}, ReplacePRs: map[int]int{}}
	m := reMissingTXT.FindStringSubmatch(src)
	if m == nil {
		return nil, fmt.Errorf("missingTXT block not found")
	}
	for _, line := range strings.Split(m[1], "\n") {
		line = stripComment(line)
		for _, q := range reQuoted.FindAllStringSubmatch(line, -1) {
			e.MissingTXT[strings.ToLower(q[1])] = true
		}
	}
	if len(e.MissingTXT) < 10 {
		return nil, fmt.Errorf("missingTXT block looks empty (%d)", len(e.MissingTXT))
	}
	if m := reAcceptPRs.FindStringSubmatch(src); m != nil {
		for _, line := range strings.Split(m[1], "\n") {
			for _, kv := range reKV.FindAllStringSubmatch(stripComment(line), -1) {
				n, _ := strconv.Atoi(kv[2])
				e.AcceptPRs[strings.ToLower(kv[1])] = n
			}
		}
	}
	if m := reReplacePRs.FindStringSubmatch(src); m != nil {
		for _, line := range strings.Split(m[1], "\n") {
			for _, kv := range reIntKV.FindAllStringSubmatch(stripComment(line), -1) {
				a, _ := strconv.Atoi(kv[1])
				b, _ := strconv.Atoi(kv[2])
				e.ReplacePRs[a] = b
			}
		}
	}
	return e, nil
}

func stripComment(l string) string {
	if i := strings.Index(l, "//"); i >= 0 {
		return l[:i]
	}
	return l
}

// Embedded returns the exceptions bundled at build time.
func Embedded() *Exceptions {
	e, err := Parse(embeddedExceptions)
	if err != nil {
		panic("embedded exceptions: " + err.Error())
	}
	return e
}

// EmbeddedSource returns the raw embedded source.
func EmbeddedSource() string { return embeddedExceptions }

// Fetch downloads and parses an exceptions file.
func Fetch(client *http.Client, url string) (*Exceptions, string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", err
	}
	e, err := Parse(string(b))
	return e, string(b), err
}

// TXT result statuses.
const (
	TXTValid   = "valid"   // _psl TXT present with a PR link
	TXTPresent = "present" // _psl TXT present but no recognisable PR link
	TXTMissing = "missing" // no _psl TXT, not exempt -> non-compliant
	TXTExempt  = "exempt"  // no _psl TXT, exempt (grandfathered)
	TXTUnknown = "unknown" // lookup inconclusive
)

// Evaluate classifies a _psl TXT lookup for a private rule name.
// dnsStatus is a dnscheck status, records are TXT strings.
func (e *Exceptions) Evaluate(rule string, dnsOK bool, dnsConclusive bool, records []string) (status string, prs []int) {
	for _, r := range records {
		for _, m := range rePR.FindAllStringSubmatch(r, -1) {
			n, _ := strconv.Atoi(m[1])
			prs = append(prs, n)
		}
	}
	switch {
	case dnsOK && len(prs) > 0:
		return TXTValid, prs
	case dnsOK && len(records) > 0:
		return TXTPresent, nil
	case !dnsConclusive:
		return TXTUnknown, nil
	case e.MissingTXT[strings.ToLower(rule)]:
		return TXTExempt, nil
	default:
		return TXTMissing, nil
	}
}

// TXTName returns the DNS name to query for a private rule. Wildcard rules
// (*.foo.example) are checked at _psl.foo.example, per the PSL guidelines.
func TXTName(ruleName string) string { return "_psl." + ruleName }

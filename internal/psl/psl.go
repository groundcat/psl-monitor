// Package psl parses the Public Suffix List and derives monitoring targets.
package psl

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const (
	SectionICANN   = "icann"
	SectionPrivate = "private"

	KindNormal    = "normal"
	KindWildcard  = "wildcard"
	KindException = "exception"
)

// Rule is a single PSL rule line.
type Rule struct {
	Section   string
	Raw       string // rule as written (unicode), e.g. "*.foo.example"
	Name      string // ASCII name with "*." / "!" stripped
	UName     string // unicode form of Name
	Kind      string
	Entity    string // block header (company / TLD)
	Submitter string // "Submitted by" line (private section)
	Line      int
}

// List is a parsed PSL.
type List struct {
	Version string
	Commit  string
	SHA256  string
	Rules   []Rule
	icann   *Matcher
}

// Fetch downloads and parses the PSL.
func Fetch(client *http.Client, url string) (*List, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// ToASCII converts a (possibly unicode) domain name to lowercase ASCII.
func ToASCII(s string) string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	a, err := idna.Punycode.ToASCII(s)
	if err != nil {
		return s
	}
	return a
}

// ToUnicode converts an ASCII domain name to its unicode form.
func ToUnicode(s string) string {
	u, err := idna.Punycode.ToUnicode(s)
	if err != nil {
		return s
	}
	return u
}

// Parse parses PSL file contents.
func Parse(data []byte) (*List, error) {
	sum := sha256.Sum256(data)
	l := &List{SHA256: hex.EncodeToString(sum[:])}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	section := ""
	entity, submitter := "", ""
	blockFresh := true // true after a blank line, until the first rule
	lineNo := 0
	seen := map[string]bool{}
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			blockFresh = true
			continue
		}
		if strings.HasPrefix(line, "//") {
			c := strings.TrimSpace(strings.TrimPrefix(line, "//"))
			switch {
			case strings.HasPrefix(c, "VERSION:"):
				l.Version = strings.TrimSpace(strings.TrimPrefix(c, "VERSION:"))
			case strings.HasPrefix(c, "COMMIT:"):
				l.Commit = strings.TrimSpace(strings.TrimPrefix(c, "COMMIT:"))
			case strings.Contains(c, "===BEGIN ICANN DOMAINS==="):
				section = SectionICANN
			case strings.Contains(c, "===BEGIN PRIVATE DOMAINS==="):
				section = SectionPrivate
			case strings.Contains(c, "===END ICANN DOMAINS==="), strings.Contains(c, "===END PRIVATE DOMAINS==="):
				section = ""
			default:
				if section == "" {
					continue
				}
				if blockFresh {
					entity = c
					if i := strings.Index(c, " : "); i >= 0 {
						entity = strings.TrimSpace(c[:i])
					}
					submitter = ""
					blockFresh = false
				} else if strings.HasPrefix(strings.ToLower(c), "submitted by") && submitter == "" {
					submitter = strings.TrimSpace(c[len("submitted by"):])
				}
			}
			continue
		}
		if section == "" {
			continue
		}
		blockFresh = false
		// rule ends at first whitespace
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			line = line[:i]
		}
		raw := strings.ToLower(line)
		kind := KindNormal
		name := raw
		switch {
		case strings.HasPrefix(name, "!"):
			kind = KindException
			name = name[1:]
		case strings.HasPrefix(name, "*."):
			kind = KindWildcard
			for strings.HasPrefix(name, "*.") {
				name = name[2:]
			}
		}
		if name == "" {
			continue
		}
		key := section + "|" + raw
		if seen[key] {
			continue
		}
		seen[key] = true
		ascii := ToASCII(name)
		l.Rules = append(l.Rules, Rule{
			Section: section, Raw: raw, Name: ascii, UName: ToUnicode(ascii), Kind: kind,
			Entity: entity, Submitter: submitter, Line: lineNo,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var nI, nP int
	for _, r := range l.Rules {
		if r.Section == SectionICANN {
			nI++
		} else {
			nP++
		}
	}
	if nI < 100 || nP < 100 {
		return nil, fmt.Errorf("parsed PSL looks truncated (icann=%d private=%d)", nI, nP)
	}
	l.icann = NewMatcher(l.Rules, SectionICANN)
	return l, nil
}

// Matcher implements the PSL algorithm over a subset of rules.
type Matcher struct {
	normal, wildcard, exception map[string]bool
}

func NewMatcher(rules []Rule, section string) *Matcher {
	m := &Matcher{normal: map[string]bool{}, wildcard: map[string]bool{}, exception: map[string]bool{}}
	for _, r := range rules {
		if section != "" && r.Section != section {
			continue
		}
		switch r.Kind {
		case KindNormal:
			m.normal[r.Name] = true
		case KindWildcard:
			m.wildcard[r.Name] = true
		case KindException:
			m.exception[r.Name] = true
		}
	}
	return m
}

// PublicSuffix returns the public suffix of an ASCII domain name.
func (m *Matcher) PublicSuffix(name string) string {
	labels := strings.Split(name, ".")
	n := len(labels)
	// exception rules prevail; the longest exception match wins
	for i := 0; i < n; i++ {
		if m.exception[strings.Join(labels[i:], ".")] {
			return strings.Join(labels[i+1:], ".")
		}
	}
	best := 1 // implicit "*" rule
	for i := 0; i < n; i++ {
		cand := strings.Join(labels[i:], ".")
		if m.normal[cand] && n-i > best {
			best = n - i
		}
		if i >= 1 && m.wildcard[cand] && n-i+1 > best {
			best = n - i + 1
		}
	}
	return strings.Join(labels[n-best:], ".")
}

// Registrable returns the ICANN public suffix + 1 label of name ("expirable" domain).
// If name itself is an ICANN public suffix it is returned unchanged.
func (m *Matcher) Registrable(name string) (registrable, suffix string) {
	suffix = m.PublicSuffix(name)
	if suffix == name {
		return name, suffix
	}
	rest := strings.TrimSuffix(name, "."+suffix)
	labels := strings.Split(rest, ".")
	return labels[len(labels)-1] + "." + suffix, suffix
}

// ICANN returns a matcher over ICANN rules only.
func (l *List) ICANN() *Matcher { return l.icann }

// Target is a monitoring target derived from the list.
type Target struct {
	Section string
	Name    string // ASCII
	UName   string
	Suffix  string // ICANN suffix the name is registered under ("" for TLDs)
	TLD     string
	Entity  string
	Rules   []int // indices into List.Rules
}

// Targets derives deduplicated targets:
//   - private: ICANN suffix + 1 label of each private rule
//   - icann:   each ICANN rule name itself
func (l *List) Targets() []Target {
	idx := map[string]int{}
	var out []Target
	for i, r := range l.Rules {
		var name, suffix string
		if r.Section == SectionPrivate {
			name, suffix = l.icann.Registrable(r.Name)
		} else {
			name = r.Name
			if j := strings.IndexByte(name, '.'); j >= 0 {
				suffix = name[j+1:]
			}
		}
		key := r.Section + "|" + name
		k, ok := idx[key]
		if !ok {
			tld := name
			if j := strings.LastIndexByte(name, '.'); j >= 0 {
				tld = name[j+1:]
			}
			out = append(out, Target{Section: r.Section, Name: name, UName: ToUnicode(name), Suffix: suffix, TLD: tld, Entity: r.Entity})
			k = len(out) - 1
			idx[key] = k
		}
		out[k].Rules = append(out[k].Rules, i)
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Section != out[b].Section {
			return out[a].Section < out[b].Section
		}
		return out[a].Name < out[b].Name
	})
	return out
}

// HTTPClient is a sane default client for fetching lists.
func HTTPClient() *http.Client { return &http.Client{Timeout: 60 * time.Second} }

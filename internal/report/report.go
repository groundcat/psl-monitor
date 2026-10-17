// Package report renders plain-text reports of flagged targets.
package report

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/mailer"
	"psl-monitor/internal/store"
)

// Build creates the report body and attachments.
func Build(st *store.Store, baseURL string, since time.Time) (string, []mailer.Attachment, error) {
	now := time.Now().UTC()
	snap, _ := st.LatestSnapshot()
	var atts []mailer.Attachment
	var body strings.Builder
	fmt.Fprintf(&body, "PSL Monitor weekly report — %s UTC\n", now.Format("2006-01-02 15:04"))
	fmt.Fprintf(&body, "PSL version: %s  commit: %s\n\n", snap.Version, snap.Commit)

	type sec struct{ key, title string }
	for _, s := range []sec{{"private", "PRIVATE section (registrable domains)"}, {"icann", "ICANN section (suffixes)"}} {
		ts, _, err := st.SearchTargets(store.TargetFilter{Section: s.key, MinSev: analyze.SevLow, Limit: 100000})
		if err != nil {
			return "", nil, err
		}
		bySev := map[int]int{}
		newCount := 0
		for _, t := range ts {
			bySev[t.Severity]++
			if !t.FlaggedSince.IsZero() && t.FlaggedSince.After(since) {
				newCount++
			}
		}
		fmt.Fprintf(&body, "%s: %d flagged (critical %d, high %d, medium %d, low %d), %d new since %s\n",
			s.title, len(ts), bySev[5], bySev[4], bySev[3], bySev[2], newCount, since.Format("2006-01-02"))
		atts = append(atts, mailer.Attachment{Name: fmt.Sprintf("flagged-%s-%s.txt", s.key, now.Format("20060102")), Data: render(s.title, ts, since)})
	}
	// expiring soon across sections
	exp, _, _ := st.SearchTargets(store.TargetFilter{ExpBefore: now.Add(90 * 24 * time.Hour), ExpAfter: now.Add(-365 * 24 * time.Hour), Sort: "expires", Limit: 100000})
	atts = append(atts, mailer.Attachment{Name: fmt.Sprintf("expiring-90d-%s.txt", now.Format("20060102")), Data: renderExpiry(exp)})
	// _psl TXT non-compliance
	rules, total := st.ListRules(store.RuleFilter{TXT: "missing", Section: "private", Sort: "entity", Limit: 100000})
	atts = append(atts, mailer.Attachment{Name: fmt.Sprintf("psl-txt-missing-%s.txt", now.Format("20060102")), Data: renderTXT(rules)})
	fmt.Fprintf(&body, "Private rules without required _psl TXT: %d\n", total)
	fmt.Fprintf(&body, "Expiring within 90 days / recently expired: %d\n", len(exp))
	// events this week
	evs, evTotal := st.ListEvents(store.EventFilter{Since: since, Limit: 5000, ExcludeTypes: []string{"acked"}})
	atts = append(atts, mailer.Attachment{Name: fmt.Sprintf("events-%s.txt", now.Format("20060102")), Data: renderEvents(evs)})
	fmt.Fprintf(&body, "State-change events since %s: %d\n\n", since.Format("2006-01-02"), evTotal)
	if baseURL != "" {
		fmt.Fprintf(&body, "Dashboard: %s/\n", strings.TrimRight(baseURL, "/"))
	}
	body.WriteString("\nLegend: CRITICAL=confirmed expired/dropped/re-registered, HIGH=probable, MEDIUM=needs review, LOW=watch (grace period).\n")
	body.WriteString("Rows marked * were newly flagged during the report period.\n")
	return body.String(), atts, nil
}

func render(title string, ts []*store.Target, since time.Time) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s — %d flagged targets — generated %s UTC\n", title, len(ts), time.Now().UTC().Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "# columns: new, severity, name, dns_state, rdap, created, expires, flags, details\n\n")
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NEW\tSEV\tNAME\tDNS\tRDAP\tCREATED\tEXPIRES\tFLAGS\tDETAILS")
	for _, t := range ts {
		n := ""
		if !t.FlaggedSince.IsZero() && t.FlaggedSince.After(since) {
			n = "*"
		}
		var msgs []string
		for _, f := range t.Flags {
			if f.Severity >= analyze.SevLow {
				msgs = append(msgs, f.Type+"["+f.Confidence+"]: "+f.Msg)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n, strings.ToUpper(analyze.SevNames[t.Severity]), t.Name, t.DNS.State, dash(t.RDAP.Result),
			date(t.RDAP.Created), date(t.RDAP.Expires), strings.Trim(t.FlagTypes, ","), strings.Join(msgs, " | "))
	}
	tw.Flush()
	return b.Bytes()
}

func renderExpiry(ts []*store.Target) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Domains expiring within 90 days or expired within the last year (RDAP) — %d\n\n", len(ts))
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EXPIRES\tDAYS\tSECTION\tNAME\tDNS\tREGISTRAR")
	for _, t := range ts {
		days := int(time.Until(t.RDAP.Expires).Hours() / 24)
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", date(t.RDAP.Expires), days, t.Section, t.Name, t.DNS.State, dash(t.RDAPRegistrar))
	}
	tw.Flush()
	return b.Bytes()
}

func renderTXT(rs []store.Rule) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Private rules missing the required _psl TXT record (not exempt) — %d\n\n", len(rs))
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tCHECKED\tENTITY\tSUBMITTER")
	for _, r := range rs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Raw, date(r.TXTCheckedAt), r.Entity, r.Submitter)
	}
	tw.Flush()
	return b.Bytes()
}

func renderEvents(evs []store.Event) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# State-change events — %d\n\n", len(evs))
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tTYPE\tSECTION\tNAME\tFROM\tTO\tDETAIL")
	for _, e := range evs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.TS.Format("2006-01-02 15:04"), e.Type, dash(e.Section), dash(e.Name), dash(e.From), dash(e.To), e.Detail)
	}
	tw.Flush()
	return b.Bytes()
}

func date(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

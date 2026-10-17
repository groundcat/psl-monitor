package checker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"psl-monitor/internal/analyze"
	"psl-monitor/internal/compliance"
	"psl-monitor/internal/dnscheck"
	"psl-monitor/internal/psl"
	"psl-monitor/internal/rdap"
	"psl-monitor/internal/store"
)

// fakeDNS is a scriptable authoritative-ish resolver for end-to-end tests.
type fakeDNS struct {
	mu   sync.Mutex
	ns   map[string][]string // name -> NS (nil = NXDOMAIN)
	srvf map[string]bool
}

func (f *fakeDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	f.mu.Lock()
	ns, ok := f.ns[name]
	sf := f.srvf[name]
	f.mu.Unlock()
	switch {
	case sf:
		m.Rcode = dns.RcodeServerFailure
	case q.Qtype == dns.TypeTXT:
		if strings.HasPrefix(name, "_psl.") {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"https://github.com/publicsuffix/list/pull/42"}})
		} else {
			m.Rcode = dns.RcodeNameError
		}
	case !ok || ns == nil:
		m.Rcode = dns.RcodeNameError
	default:
		for _, n := range ns {
			m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: n + "."})
		}
	}
	w.WriteMsg(m)
}

func startFake(t *testing.T, f *fakeDNS) []string {
	var addrs []string
	for i := 0; i < 2; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &dns.Server{PacketConn: pc, Handler: f}
		go srv.ActivateAndServe()
		t.Cleanup(func() { srv.Shutdown() })
		addrs = append(addrs, fmt.Sprintf("%s@prov%d", pc.LocalAddr().String(), i))
	}
	return addrs
}

// TestEndToEndGrace simulates daily runs over a week with a fake clock-free
// approach: we drive the state machine through runs by rewriting LastDay.
func TestEndToEndGrace(t *testing.T) {
	b, err := os.ReadFile("/tmp/opencode/psl.dat")
	if err != nil {
		t.Skip("no local PSL copy")
	}
	l, _ := psl.Parse(b)
	st, err := store.Open(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	st.SyncList(ctx, l, nil, 0)

	f := &fakeDNS{ns: map[string][]string{}, srvf: map[string]bool{}}
	ts, _ := st.LoadTargets("private")
	for _, tg := range ts {
		f.ns[tg.Name] = []string{"ns1.example-dns.net", "ns2.example-dns.net"}
	}
	pool, err := dnscheck.NewPool(dnscheck.Options{Resolvers: startFake(t, f), QPS: 5000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ck := New(st, pool, rdap.New(rdap.Options{Overrides: map[string]string{}}), analyze.NewParking(analyze.DefaultParkingNS, analyze.DefaultParkingKeywords), compliance.Embedded(),
		Config{Grace: 5, DNSWorkers: 64, RDAPWorkers: 4, TXTWorkers: 64, TargetTimeout: 5 * time.Second, RDAPMaxAge: time.Hour}, log)

	runDay := func(day int) {
		// shift each target's LastDay back so this run counts as a new day
		st.W.Exec(`UPDATE targets SET last_day=? WHERE last_day<>''`, fmt.Sprintf("2000-01-%02d", day))
		r := &run{c: ck, rs: &runState{}, kind: KindDNSPrivate, pool: pool, rdap: ck.RDAP()}
		r.rs.phase.Store("")
		id, _ := st.CreateRun(KindDNSPrivate, "", "test", "test")
		r.id = id
		ts, _ := st.LoadTargets("private")
		start := time.Now()
		if err := r.dnsPhase(ctx, ts, false); err != nil {
			t.Fatal(err)
		}
		t.Logf("day %d: %d targets in %s", day, len(ts), time.Since(start).Round(time.Millisecond))
	}
	const gone, moved, flaky = "a2hosted.com", "addr.tools", "myaddr.io"
	runDay(1)
	f.mu.Lock()
	f.ns[gone] = nil
	f.ns[moved] = []string{"ns1.sedoparking.com", "ns2.sedoparking.com"}
	f.mu.Unlock()
	for d := 2; d <= 6; d++ {
		f.mu.Lock()
		f.srvf[flaky] = d%2 == 0 // alternates: never 5 consecutive days
		f.mu.Unlock()
		runDay(d)
		g, _ := st.GetTargetByName("private", gone)
		m, _ := st.GetTargetByName("private", moved)
		want := analyze.DNSMissing
		wantM := analyze.DNSChanging
		if d == 6 {
			want, wantM = analyze.DNSDefunct, analyze.DNSChanged
		}
		if g.DNS.State != want || m.DNS.State != wantM {
			t.Fatalf("day %d: gone=%s(%d) moved=%s(%d)", d, g.DNS.State, g.DNS.MissingDays, m.DNS.State, m.DNS.ChangedDays)
		}
	}
	fl, _ := st.GetTargetByName("private", flaky)
	if fl.DNS.State == analyze.DNSDefunct {
		t.Fatal("flaky domain must not become defunct")
	}
	m, _ := st.GetTargetByName("private", moved)
	if m.Severity != analyze.SevCritical || !strings.Contains(m.FlagTypes, ",parked,") {
		t.Fatalf("moved to parking should be critical: %d %s", m.Severity, m.FlagTypes)
	}
	g, _ := st.GetTargetByName("private", gone)
	if g.Severity < analyze.SevHigh || !strings.Contains(g.FlagTypes, ",defunct,") {
		t.Fatalf("gone: %d %s", g.Severity, g.FlagTypes)
	}
	items, total, _ := st.SearchTargets(store.TargetFilter{MinSev: analyze.SevMedium, Section: "private"})
	if total != 2 {
		var names []string
		for _, i := range items {
			names = append(names, i.Name+":"+i.FlagTypes)
		}
		t.Fatalf("expected exactly 2 medium+ findings, got %d: %v", total, names)
	}
	evs, _ := st.ListEvents(store.EventFilter{Type: "dns_state"})
	if len(evs) < 4 {
		t.Fatalf("expected state transition events, got %d", len(evs))
	}
}

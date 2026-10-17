package analyze

import (
	"testing"
	"time"

	"psl-monitor/internal/dnscheck"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func day(n int) time.Time { return t0.Add(time.Duration(n) * 24 * time.Hour) }

func ok(n int, ns ...string) Observation {
	return Observation{Status: dnscheck.StatusOK, Records: ns, At: day(n)}
}
func neg(n int, st string) Observation { return Observation{Status: st, At: day(n)} }

func TestDefunctAfterGrace(t *testing.T) {
	s := &NSState{}
	Apply(s, ok(0, "a.ns", "b.ns"), 5)
	if s.State != DNSOK {
		t.Fatal(s.State)
	}
	for i := 1; i <= 4; i++ {
		Apply(s, neg(i, dnscheck.StatusServFail), 5)
		if s.State != DNSMissing {
			t.Fatalf("day %d: %s", i, s.State)
		}
	}
	// same-day re-run must not advance the counter
	Apply(s, Observation{Status: dnscheck.StatusNXDomain, At: day(4).Add(time.Hour)}, 5)
	if s.State != DNSMissing || s.MissingDays != 4 {
		t.Fatalf("same-day rerun advanced: %s %d", s.State, s.MissingDays)
	}
	ev := Apply(s, neg(5, dnscheck.StatusNXDomain), 5)
	if s.State != DNSDefunct || ev == nil {
		t.Fatalf("want defunct got %s", s.State)
	}
	// inconclusive error keeps state
	Apply(s, neg(6, dnscheck.StatusError), 5)
	if s.State != DNSDefunct {
		t.Fatal(s.State)
	}
	// recovery
	Apply(s, ok(7, "b.ns"), 5)
	if s.State != DNSOK || s.MissingDays != 0 {
		t.Fatal(s.State)
	}
}

func TestBlipDoesNotFlag(t *testing.T) {
	s := &NSState{}
	Apply(s, ok(0, "a.ns"), 5)
	Apply(s, neg(1, dnscheck.StatusTimeout), 5)
	Apply(s, ok(2, "a.ns"), 5)
	if s.State != DNSOK || s.MissingDays != 0 {
		t.Fatal(s.State)
	}
}

func TestPartialOverlapIsUnchanged(t *testing.T) {
	s := &NSState{}
	Apply(s, ok(0, "ns1.cctld.net", "ns2.cctld.net"), 5)
	Apply(s, ok(1, "ns1.cctld.net", "ns2.cctld.net", "ns3.cctld.net"), 5)
	Apply(s, ok(2, "ns3.cctld.net"), 5) // overlaps updated baseline
	if s.State != DNSOK {
		t.Fatal(s.State)
	}
}

func TestChangedHands(t *testing.T) {
	s := &NSState{}
	Apply(s, ok(0, "ns1.cctld.net", "ns2.cctld.net"), 5)
	for i := 1; i <= 4; i++ {
		Apply(s, ok(i, "ns1.sedoparking.com", "ns2.sedoparking.com"), 5)
		if s.State != DNSChanging {
			t.Fatalf("day %d %s", i, s.State)
		}
	}
	Apply(s, ok(5, "ns2.sedoparking.com", "ns1.sedoparking.com"), 5)
	if s.State != DNSChanged {
		t.Fatal(s.State)
	}
	// baseline is retained until acknowledged
	if s.Baseline[0] != "ns1.cctld.net" {
		t.Fatal(s.Baseline)
	}
	Acknowledge(s, day(6))
	if s.State != DNSOK || s.Baseline[0] != "ns1.sedoparking.com" || s.Previous[0] != "ns1.cctld.net" {
		t.Fatalf("%+v", s)
	}
}

func TestChangeRevertsWithinGrace(t *testing.T) {
	s := &NSState{}
	Apply(s, ok(0, "a"), 5)
	Apply(s, ok(1, "z"), 5)
	Apply(s, ok(2, "a"), 5)
	if s.State != DNSOK || s.ChangedDays != 0 {
		t.Fatal(s.State)
	}
}

func TestNeverDelegatedThenAppears(t *testing.T) {
	s := &NSState{}
	for i := 0; i < 5; i++ {
		Apply(s, neg(i, dnscheck.StatusNoData), 5)
	}
	if s.State != DNSNoNS {
		t.Fatal(s.State)
	}
	Apply(s, ok(5, "evil.ns"), 5)
	if s.State != DNSAppeared {
		t.Fatal(s.State)
	}
}

func TestFirstSeenNotAppeared(t *testing.T) {
	s := &NSState{}
	Apply(s, neg(0, dnscheck.StatusNoData), 5)
	Apply(s, ok(1, "a"), 5)
	if s.State != DNSOK {
		t.Fatal(s.State)
	}
}

func TestEvaluateConfidence(t *testing.T) {
	now := day(10)
	base := NSState{State: DNSDefunct, MissingDays: 5, LastStatus: "nxdomain", Baseline: []string{"a"}}
	f := Evaluate(Input{Section: "private", DNS: base, RDAP: RDAPInfo{Result: "found", Expires: day(5)}, Grace: 5, Now: now})
	if f[0].Severity != SevCritical || f[0].Type != FlagExpired {
		t.Fatalf("%+v", f)
	}
	var def Flag
	for _, x := range f {
		if x.Type == FlagDefunct {
			def = x
		}
	}
	if def.Confidence != ConfConfirmed {
		t.Fatalf("%+v", def)
	}
	f = Evaluate(Input{Section: "private", DNS: base, RDAP: RDAPInfo{Result: "unsupported"}, Grace: 5, Now: now})
	if len(f) != 1 || f[0].Confidence != ConfMedium || f[0].Severity != SevHigh {
		t.Fatalf("%+v", f)
	}
	f = Evaluate(Input{Section: "private", DNS: base, RDAP: RDAPInfo{Result: "found", Expires: day(1000)}, Grace: 5, Now: now})
	if len(f) != 1 || f[0].Severity != SevMedium {
		t.Fatalf("%+v", f)
	}
}

func TestEvaluateExpiryWindows(t *testing.T) {
	now := day(0)
	cases := map[time.Duration]string{
		10 * 24 * time.Hour:  FlagExpiringSoon,
		60 * 24 * time.Hour:  FlagExpiring90,
		200 * 24 * time.Hour: FlagShortTerm,
	}
	for d, want := range cases {
		f := Evaluate(Input{Section: "private", DNS: NSState{State: DNSOK}, RDAP: RDAPInfo{Result: "found", Expires: now.Add(d), Created: day(-4000)}, Now: now})
		if len(f) != 1 || f[0].Type != want {
			t.Errorf("%v: %+v", d, f)
		}
	}
	f := Evaluate(Input{Section: "icann", DNS: NSState{State: DNSOK}, RDAP: RDAPInfo{Result: "found", Expires: now.Add(200 * 24 * time.Hour)}, Now: now})
	if len(f) != 0 {
		t.Errorf("icann short term should not flag: %+v", f)
	}
}

func TestEvaluateICANNNotFound(t *testing.T) {
	// many ICANN labels are not registry objects; 404 without history is not a finding
	f := Evaluate(Input{Section: "icann", DNS: NSState{State: DNSNoNS}, RDAP: RDAPInfo{Result: "not_found"}, Now: day(0)})
	if len(f) != 0 {
		t.Fatalf("%+v", f)
	}
	f = Evaluate(Input{Section: "icann", DNS: NSState{State: DNSNoNS}, RDAP: RDAPInfo{Result: "not_found", EverFound: true}, Now: day(0)})
	if len(f) != 1 || f[0].Type != FlagDropped {
		t.Fatalf("%+v", f)
	}
}

func TestParking(t *testing.T) {
	p := NewParking(DefaultParkingNS, DefaultParkingKeywords)
	got := p.Match([]string{"ns1.sedoparking.com.", "ns3.sedoparking.com", "dns1.registrar-servers.com", "ns1.sparkasse.de", "expired-domain.domrobot.com", "ns1.domrobot.com", "ns1.jordan.com", "ns.parked-domain.example"})
	want := []string{"ns1.sedoparking.com", "ns3.sedoparking.com", "expired-domain.domrobot.com", "ns.parked-domain.example"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

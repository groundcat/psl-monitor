// Package analyze contains the NS state machine and flag evaluation.
// It is pure logic with no I/O so it can be unit-tested exhaustively.
package analyze

import (
	"sort"
	"strings"
	"time"

	"psl-monitor/internal/dnscheck"
)

// DNS states.
const (
	DNSUnknown  = "unknown"  // never observed conclusively
	DNSOK       = "ok"       // NS present and overlapping baseline
	DNSNoNS     = "no_ns"    // never had NS since tracking began (normal for many ICANN labels)
	DNSMissing  = "missing"  // had NS, now missing, within grace period
	DNSDefunct  = "defunct"  // had NS, missing for >= grace distinct days
	DNSChanging = "changing" // NS disjoint from baseline, within grace period
	DNSChanged  = "changed"  // NS disjoint from baseline for >= grace distinct days
	DNSAppeared = "appeared" // had no NS for >= grace days, now has NS
)

// NSState is the persisted per-target DNS state.
type NSState struct {
	Baseline   []string  // last accepted NS set ("known good")
	BaselineAt time.Time // when baseline was (last) accepted
	Previous   []string  // baseline before a confirmed change/appearance
	Current    []string  // last observed NS set (union across resolvers)
	LastStatus string    // last lookup status
	LastOKAt   time.Time
	State      string

	MissingDays  int
	MissingSince time.Time
	ChangedDays  int
	ChangedSince time.Time
	NegDays      int // consecutive negative days while no baseline
	LastDay      string
	Inconsistent bool
}

// Observation is one consolidated lookup.
type Observation struct {
	Status       string
	Records      []string
	Inconsistent bool
	At           time.Time
}

// Event describes a state transition worth recording.
type Event struct {
	From, To string
	Detail   string
}

// Apply advances the state machine. Counters advance at most once per UTC
// day, so manual re-runs on the same day do not shorten the grace period.
// grace is the number of distinct days an anomaly must persist.
func Apply(s *NSState, o Observation, grace int) *Event {
	if grace < 1 {
		grace = 1
	}
	if s.State == "" {
		s.State = DNSUnknown
	}
	o.Records = SortedCopy(o.Records)
	day := o.At.UTC().Format("2006-01-02")
	newDay := day != s.LastDay
	prev := s.State
	s.LastStatus = o.Status
	s.Inconsistent = o.Inconsistent

	switch {
	case o.Status == dnscheck.StatusOK:
		s.Current = o.Records
		s.LastOKAt = o.At
		s.MissingDays, s.MissingSince = 0, time.Time{}
		switch {
		case len(s.Baseline) == 0:
			// first sighting, or delegation (re)appeared after a long absence
			if s.NegDays >= grace {
				s.State = DNSAppeared
			} else if s.State != DNSAppeared {
				s.State = DNSOK
			}
			s.Baseline, s.BaselineAt = o.Records, o.At
			s.NegDays = 0
		case dnscheck.Overlaps(o.Records, s.Baseline):
			// at least one known NS persists: unchanged. Track benign
			// additions/removals so the baseline follows gradual migrations.
			s.ChangedDays, s.ChangedSince = 0, time.Time{}
			if s.State != DNSAppeared {
				s.State = DNSOK
			}
			s.Baseline, s.BaselineAt = o.Records, o.At
		default:
			// disjoint from baseline
			if s.ChangedDays == 0 {
				s.ChangedSince = o.At
				s.ChangedDays = 1
			} else if newDay {
				s.ChangedDays++
			}
			if s.ChangedDays >= grace {
				s.State = DNSChanged
			} else if s.State != DNSChanged {
				s.State = DNSChanging
			}
		}
	case dnscheck.IsMissing(o.Status):
		s.Current = nil
		if len(s.Baseline) == 0 {
			if s.NegDays == 0 || newDay {
				s.NegDays++
			}
			if s.State != DNSAppeared {
				s.State = DNSNoNS
			}
			break
		}
		s.ChangedDays, s.ChangedSince = 0, time.Time{}
		if s.MissingDays == 0 {
			s.MissingSince = o.At
			s.MissingDays = 1
		} else if newDay {
			s.MissingDays++
		}
		if s.MissingDays >= grace {
			s.State = DNSDefunct
		} else if s.State != DNSDefunct {
			s.State = DNSMissing
		}
	default:
		// inconclusive (local error); keep state, record status only
	}
	s.LastDay = day
	if s.State != prev {
		return &Event{From: prev, To: s.State, Detail: o.Status + " " + strings.Join(o.Records, ",")}
	}
	return nil
}

// Acknowledge accepts the current NS set as the new baseline and clears
// sticky states (changed/appeared/defunct).
func Acknowledge(s *NSState, now time.Time) {
	if len(s.Baseline) > 0 {
		s.Previous = s.Baseline
	}
	if len(s.Current) > 0 {
		s.Baseline, s.BaselineAt = s.Current, now
		s.State = DNSOK
	} else {
		s.Baseline, s.BaselineAt = nil, time.Time{}
		s.State = DNSNoNS
	}
	s.MissingDays, s.ChangedDays, s.NegDays = 0, 0, 0
	s.MissingSince, s.ChangedSince = time.Time{}, time.Time{}
}

// SortedCopy returns a sorted copy.
func SortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

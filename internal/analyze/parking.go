package analyze

import (
	"bufio"
	"strings"
	"sync"
)

// DefaultParkingNS is a built-in copy of the community parking NS list
// (https://gist.github.com/CodeAlDente/33aeb7ff369e7ecd2d52abd0d0ee7d59).
// It is neither exhaustive nor free of false positives.
const DefaultParkingNS = `# Afternic:
ns1.afternic.com
ns2.afternic.com
# Sedo:
ns1.sedoparking.com
ns2.sedoparking.com
# ParkingCrew:
ns1.parkingcrew.net
ns2.parkingcrew.net
# Bodis:
ns1.bodis.com
ns2.bodis.com
# Uniregistry:
ns1.uniregistrymarket.link
ns2.uniregistrymarket.link
# Above.com:
ns1.above.com
ns2.above.com
# Namecheap Parking:
parkingpage.namecheap.com
# dan.com:
ns1.dan.com
ns2.dan.com
# ParkLogic Pty Ltd.:
ns1.parklogic.com
ns2.parklogic.com
# Domrobot.com:
expired-domain.domrobot.com
please-renew-domain.domrobot.com
`

// DefaultParkingKeywords are substrings that suggest parking/expiry NS.
var DefaultParkingKeywords = []string{"park", "expired", "expiry", "expire", "renew", "suspended", "forsale", "for-sale", "undeveloped", "hugedomains"}

// keywordAllow suppresses known false positives (substring "park" etc. in legitimate NS).
var keywordAllow = []string{"sparkasse", "parkinson"}

// Parking matches NS hostnames against exact hosts, parent domains and keywords.
type Parking struct {
	mu       sync.RWMutex
	hosts    map[string]bool
	domains  map[string]bool // registrable part of listed hosts, e.g. sedoparking.com
	keywords []string
}

// NewParking builds a matcher from a host list (one per line, # comments) and keywords.
func NewParking(list string, keywords []string) *Parking {
	p := &Parking{}
	p.Load(list, keywords)
	return p
}

// Load replaces the matcher's data.
func (p *Parking) Load(list string, keywords []string) {
	hosts := map[string]bool{}
	domains := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(list))
	for sc.Scan() {
		l := strings.ToLower(strings.TrimSpace(sc.Text()))
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		l = strings.TrimSuffix(l, ".")
		hosts[l] = true
		parts := strings.Split(l, ".")
		if len(parts) >= 2 {
			domains[strings.Join(parts[len(parts)-2:], ".")] = true
		}
	}
	var kw []string
	for _, k := range keywords {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			kw = append(kw, k)
		}
	}
	p.mu.Lock()
	p.hosts, p.domains, p.keywords = hosts, domains, kw
	p.mu.Unlock()
}

// Match returns the NS hosts that look like parking.
func (p *Parking) Match(ns []string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []string
	for _, h := range ns {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if p.hosts[h] {
			out = append(out, h)
			continue
		}
		parts := strings.Split(h, ".")
		if len(parts) >= 2 && p.domains[strings.Join(parts[len(parts)-2:], ".")] {
			// namecheap.com / above.com etc. host legit DNS too; only exact parent of a
			// *dedicated* parking domain counts. Treat generic providers as non-matches.
			if !genericProvider[strings.Join(parts[len(parts)-2:], ".")] {
				out = append(out, h)
				continue
			}
		}
		allowed := false
		for _, a := range keywordAllow {
			if strings.Contains(h, a) {
				allowed = true
			}
		}
		if allowed {
			continue
		}
		for _, k := range p.keywords {
			if strings.Contains(h, k) {
				out = append(out, h)
				break
			}
		}
	}
	return out
}

// genericProvider lists domains in the parking list that also run regular DNS.
var genericProvider = map[string]bool{"namecheap.com": true, "domrobot.com": true, "above.com": true}

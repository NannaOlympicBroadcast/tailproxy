package proxy

import (
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

// bypassStats counts, for transparently captured connections, where the
// domain came from (DESIGN §4.8 L0), so the effect of apps that resolve
// through their own DoH can be measured rather than guessed.
type bypassStats struct {
	transparent, fakeip, sniffed, unknown, ech, dohBlocked atomic.Int64

	mu         sync.Mutex
	unknownDst map[string]int64 // ip:port with no domain -> count
}

// maxUnknownDests bounds the table of unknown destinations.
const maxUnknownDests = 256

func (b *bypassStats) observe(d Dest) {
	b.transparent.Add(1)
	switch {
	case d.DomainSrc == "fakeip":
		b.fakeip.Add(1)
	case d.Domain != "":
		b.sniffed.Add(1)
	default:
		b.unknown.Add(1)
		key := net.JoinHostPort(d.IP.String(), strconv.Itoa(int(d.Port)))
		b.mu.Lock()
		if b.unknownDst == nil {
			b.unknownDst = map[string]int64{}
		}
		if _, ok := b.unknownDst[key]; ok || len(b.unknownDst) < maxUnknownDests {
			b.unknownDst[key]++
		}
		b.mu.Unlock()
	}
	if d.ECH {
		b.ech.Add(1)
	}
}

// BypassView is the JSON form of bypassStats.
type BypassView struct {
	Transparent int64       `json:"transparent"` // captured connections
	FakeIP      int64       `json:"fakeip"`      // domain from the FakeIP table
	Sniffed     int64       `json:"sniffed"`     // domain from SNI / Host
	Unknown     int64       `json:"unknown"`     // no domain: IP rules only
	ECH         int64       `json:"ech"`         // ClientHello with ECH
	DoHBlocked  int64       `json:"doh_blocked"` // refused: SNI is a DoH endpoint
	TopUnknown  []DestCount `json:"top_unknown,omitempty"`
}

// DestCount is one destination with no known domain.
type DestCount struct {
	Dest  string `json:"dest"`
	Count int64  `json:"count"`
}

func (b *bypassStats) view() BypassView {
	v := BypassView{Transparent: b.transparent.Load(), FakeIP: b.fakeip.Load(), Sniffed: b.sniffed.Load(),
		Unknown: b.unknown.Load(), ECH: b.ech.Load(), DoHBlocked: b.dohBlocked.Load()}
	b.mu.Lock()
	for d, n := range b.unknownDst {
		v.TopUnknown = append(v.TopUnknown, DestCount{d, n})
	}
	b.mu.Unlock()
	sort.Slice(v.TopUnknown, func(i, j int) bool {
		if v.TopUnknown[i].Count != v.TopUnknown[j].Count {
			return v.TopUnknown[i].Count > v.TopUnknown[j].Count
		}
		return v.TopUnknown[i].Dest < v.TopUnknown[j].Dest
	})
	if len(v.TopUnknown) > 20 {
		v.TopUnknown = v.TopUnknown[:20]
	}
	return v
}

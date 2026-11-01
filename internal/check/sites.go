package check

import (
	"sort"

	"github.com/kd-011/unlisted/internal/discover"
)

// Site is one public hostname after merging every source that serves it. A
// tunnel in front of Caddy lists the same host twice; the human sees one site.
type Site struct {
	Host   string
	Via    []string // tunnel | caddy | nginx
	Origin discover.Origin
	Auth   bool
	AuthBy string
	Locs   []Location
}

// ViaName is the human word for a source.
func ViaName(source string) string {
	if source == "cloudflared" {
		return "tunnel"
	}
	return source
}

// MergeSites groups exposures by hostname, sorted by host.
func MergeSites(exposures []discover.Exposure) []*Site {
	byHost := map[string]*Site{}
	var sites []*Site
	for _, e := range exposures {
		s := byHost[e.Host]
		if s == nil {
			s = &Site{Host: e.Host}
			byHost[e.Host] = s
			sites = append(sites, s)
		}
		s.Via = append(s.Via, ViaName(e.Source))
		s.Locs = append(s.Locs, Location{Source: e.Source, File: e.File, Line: e.Line})
		// A reverse proxy knows the real backend; a tunnel usually just points
		// at the proxy. Prefer the proxy's answer when both exist.
		if !e.Origin.IsZero() && (s.Origin.IsZero() || e.Source != "cloudflared") {
			s.Origin = e.Origin
		}
		if e.Auth {
			s.Auth, s.AuthBy = true, e.AuthBy
		}
	}
	sort.SliceStable(sites, func(i, j int) bool { return sites[i].Host < sites[j].Host })
	return sites
}

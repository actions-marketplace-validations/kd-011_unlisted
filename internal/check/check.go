package check

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kd-011/unlisted/internal/discover"
	"github.com/kd-011/unlisted/internal/probe"
	"github.com/kd-011/unlisted/internal/registry"
)

// Input is everything a check needs. Nothing in here is read from disk or the
// network by this package, which is what keeps it testable.
type Input struct {
	Registry *registry.Registry
	Snap     discover.Snapshot
	Probes   []probe.Result // nil unless --probe ran
	ProbeRan bool
	// CertWarnDays is the "expires soon" threshold; 0 means 14.
	CertWarnDays int
}

// NoRegistryNote is shown when there was no registry file to compare against.
const NoRegistryNote = "No registry.yml here, so this lists everything the machine exposes. Run unlisted init to write a registry from it, then edit the names and auth lines."

type Report struct {
	Registry string
	Services int
	Sources  []discover.Status
	Findings []Finding
	Probes   []probe.Result
	ProbeRan bool
	// Notes are things that could not be checked, said plainly so a clean
	// report is never mistaken for a complete one.
	Notes []string
	// NoRegistry is set when no registry file existed: every finding is then
	// "unregistered" and the report is a list of what the machine exposes.
	NoRegistry bool
}

func Run(in Input) Report {
	if in.CertWarnDays == 0 {
		in.CertWarnDays = 14
	}
	r := Report{
		Registry: in.Registry.Path,
		Services: len(in.Registry.Services),
		Sources:  in.Snap.Sources,
		Probes:   in.Probes,
		ProbeRan: in.ProbeRan,
	}
	c := &checker{in: in, rep: &r}
	c.index()
	c.unregisteredHosts()
	c.registered()
	c.unregisteredPorts()
	c.certs()
	c.dashboardTunnel()
	sortFindings(r.Findings)
	return r
}

type checker struct {
	in  Input
	rep *Report

	sites      []*Site
	hostSrcs   int // hostname sources that loaded
	procLoaded bool
	listening  map[int]bool // any bind, loopback included
	probes     map[string]probe.Result
	// ports explained by something declared or already reported
	explained map[int]bool
	skipped   int
}

func (c *checker) index() {
	snap := c.in.Snap
	for _, n := range []string{"cloudflared", "caddy", "nginx"} {
		if snap.Loaded(n) {
			c.hostSrcs++
		}
	}
	c.procLoaded = snap.Loaded("proc")
	c.listening = map[int]bool{}
	for _, l := range snap.Listeners {
		c.listening[l.Port] = true
	}
	c.probes = map[string]probe.Result{}
	for _, p := range c.in.Probes {
		c.probes[p.Host] = p
	}

	c.sites = MergeSites(snap.Exposures)

	c.explained = map[int]bool{}
	for _, s := range c.in.Registry.Services {
		if p := s.EffectivePort(); p != 0 {
			c.explained[p] = true
		}
	}
	for _, s := range c.sites {
		for _, p := range c.originPorts(s.Origin) {
			c.explained[p] = true
		}
	}
}

// originPorts are the host-side ports an origin stands for. A local origin is
// its own port. An origin that names a Docker container (Caddy inside the same
// compose network: reverse_proxy jellyfin:8096) stands for the host ports that
// container publishes that private port on.
func (c *checker) originPorts(o discover.Origin) []int {
	var out []int
	if o.Local && o.Port != 0 {
		out = append(out, o.Port)
	}
	for _, l := range c.in.Snap.Listeners {
		if l.Container != "" && l.Container == o.Host && l.ContainerPort == o.Port {
			out = append(out, l.Port)
		}
	}
	return out
}

// hostMatches reports whether a registry host covers an exposure host.
func hostMatches(registryHost, exposureHost string) bool {
	if registryHost == exposureHost {
		return true
	}
	if strings.HasPrefix(registryHost, "*.") && strings.HasSuffix(exposureHost, registryHost[1:]) &&
		!strings.HasPrefix(exposureHost, "*.") {
		return true
	}
	return false
}

// serving finds the site serving a registry host, exact match first.
func (c *checker) serving(host string) *Site {
	var wild *Site
	for _, s := range c.sites {
		if s.Host == host {
			return s
		}
		if strings.HasPrefix(s.Host, "*.") && strings.HasSuffix(host, s.Host[1:]) && wild == nil {
			wild = s
		}
	}
	return wild
}

func (c *checker) registeredHost(h string) bool {
	for _, s := range c.in.Registry.Services {
		if s.Host != "" && hostMatches(s.Host, h) {
			return true
		}
	}
	return false
}

func (c *checker) add(f Finding) { c.rep.Findings = append(c.rep.Findings, f) }

func (c *checker) unregisteredHosts() {
	for _, s := range c.sites {
		if c.registeredHost(s.Host) {
			continue
		}
		sev := High
		msg := "served via " + strings.Join(dedupe(s.Via), " + ")
		if !s.Origin.IsZero() {
			msg += " → " + s.Origin.Addr()
		} else {
			sev = Medium // nothing behind it to compromise: a static site
		}
		if s.Auth {
			msg += " · auth detected (" + s.AuthBy + ")"
			sev = Medium
		} else {
			msg += " · no auth detected"
		}
		if s.Origin.Local && s.Origin.Port != 0 && c.publicPort(s.Origin.Port) {
			msg += " · origin also open on all interfaces"
		}
		c.add(Finding{
			Type: Unregistered, Severity: sev, Service: s.Host, Host: s.Host, Port: s.Origin.Port,
			Message: msg, Where: s.Locs,
			Fix: "add it to the registry, or remove the " + ruleNoun(s.Via),
		})
	}
}

func ruleNoun(via []string) string {
	switch via[0] {
	case "tunnel":
		return "tunnel ingress rule"
	case "caddy":
		return "Caddy site"
	}
	return "nginx server block"
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (c *checker) publicPort(p int) bool {
	for _, l := range c.in.Snap.Listeners {
		if l.Port == p && l.Public {
			return true
		}
	}
	return false
}

func (c *checker) registered() {
	for _, svc := range c.in.Registry.Services {
		if svc.Ignore {
			continue
		}
		reg := Location{Source: "registry", File: c.in.Registry.Path, Line: svc.Line}
		port := svc.EffectivePort()
		var st *Site
		if svc.Host != "" {
			st = c.serving(svc.Host)
		}
		pr, probed := c.probes[svc.Host]

		c.dead(svc, st, port, reg, pr, probed)

		if st == nil {
			continue
		}
		hint := ""
		if probed {
			hint = pr.AuthHint
		}
		if svc.Auth == registry.AuthUnset && !st.Auth && hint == "" {
			c.add(Finding{
				Type: NoAuth, Severity: Medium, Service: svc.Label(), Host: svc.Host, Port: st.Origin.Port,
				Message: fmt.Sprintf("%s → %s · no auth detected, none declared",
					strings.Join(dedupe(st.Via), " + "), originOr(st.Origin)),
				Where: append([]Location{reg}, st.Locs...),
				Fix:   "declare auth: in the registry (auth: none to accept it)",
			})
		}
		if po := st.Origin.Port; po != 0 && port != 0 && st.Origin.Scheme != "unix" && !c.portAliases(st.Origin, port) {
			c.add(Finding{
				Type: Drift, Severity: Medium, Service: svc.Label(), Host: svc.Host, Port: po,
				Message: fmt.Sprintf("registry says port %d, %s routes it to %s",
					port, strings.Join(dedupe(st.Via), " + "), originOr(st.Origin)),
				Where: append([]Location{reg}, st.Locs...),
				Fix:   fmt.Sprintf("set port: %d in the registry, or point the rule back at %d", po, port),
			})
		}
	}
}

// portAliases reports whether the registry port is another valid name for the
// origin port, through a Docker publish (host 8097 -> container 8096).
func (c *checker) portAliases(o discover.Origin, regPort int) bool {
	if o.Port == regPort {
		return true
	}
	for _, p := range c.originPorts(o) {
		if p == regPort {
			return true
		}
	}
	return false
}

func originOr(o discover.Origin) string {
	if o.IsZero() {
		return "a static response"
	}
	return o.Addr()
}

func (c *checker) dead(svc registry.Service, st *Site, port int, reg Location, pr probe.Result, probed bool) {
	var reason string
	var where []Location
	fix := ""

	switch {
	case svc.Host != "" && c.hostSrcs > 0 && st == nil:
		reason = fmt.Sprintf("no tunnel or proxy rule serves %s", svc.Host)
		fix = "remove it from the registry, or restore the rule"
	case st != nil && st.Origin.Local && st.Origin.Port != 0 && c.procLoaded && !c.listening[st.Origin.Port]:
		reason = fmt.Sprintf("%s → %s, but nothing is listening on port %d",
			strings.Join(dedupe(st.Via), " + "), st.Origin.Addr(), st.Origin.Port)
		where = st.Locs
		fix = "start the service, or remove the rule and the registry entry"
	case st == nil && port != 0 && c.procLoaded && (svc.Host == "" || c.hostSrcs == 0) &&
		(svc.URL == "" || isLocal(svc.URLHost())) && !c.listening[port]:
		reason = fmt.Sprintf("nothing is listening on port %d", port)
		fix = "start the service, or remove it from the registry"
	}

	if reason == "" && probed && pr.Dead() {
		reason = "probe failed: " + probeSummary(pr)
		fix = "check the service is running, or remove it from the registry"
	} else if reason != "" && probed && pr.Dead() {
		reason += "; probe: " + probeSummary(pr)
	}

	if reason == "" {
		// Count services that had no way to be verified, so silence is honest.
		if svc.Host != "" && c.hostSrcs == 0 && (port == 0 || !c.procLoaded) && !probed {
			c.skipped++
			c.rep.Notes = appendNote(c.rep.Notes, "services-unverified", c.skipped)
		}
		return
	}
	loc := []Location{reg}
	loc = append(loc, where...)
	c.add(Finding{
		Type: Dead, Severity: Medium, Service: svc.Label(), Host: svc.Host, Port: port,
		Message: reason, Where: loc, Fix: fix,
	})
}

// appendNote keeps one running "N services could not be verified" note.
func appendNote(notes []string, key string, n int) []string {
	msg := fmt.Sprintf("%d registry %s could not be checked for DEAD: no tunnel, proxy or /proc data to check against",
		n, plural(n, "service", "services"))
	for i := range notes {
		if strings.Contains(notes[i], "could not be checked for DEAD") {
			notes[i] = msg
			return notes
		}
	}
	return append(notes, msg)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func isLocal(h string) bool {
	return discover.ParseOrigin(h).Local
}

func probeSummary(p probe.Result) string {
	if p.Err != "" {
		return p.Err
	}
	return "HTTP " + strconv.Itoa(p.Status)
}

// A bare listening port is real but low-value. Services that are almost never
// meant to face a network are worth more than a line of noise.
var riskyPorts = map[int]string{
	2375: "Docker API, unauthenticated", 3306: "MySQL", 5432: "PostgreSQL", 5984: "CouchDB",
	6379: "Redis", 9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB",
}

var proxyNames = map[string]string{"caddy": "caddy", "nginx": "nginx", "cloudflared": "cloudflared"}

func (c *checker) unregisteredPorts() {
	for _, l := range c.in.Snap.Listeners {
		if !l.Public || c.explained[l.Port] || c.isOwnProxy(l) {
			continue
		}
		name := l.Name()
		label := name
		if label == "" {
			label = "port " + strconv.Itoa(l.Port)
		}
		msg := fmt.Sprintf("listening on %s:%d", l.Addr, l.Port)
		short := l.Addr
		sev := Low
		if l.Container != "" {
			msg += " (container " + l.Container + ")"
			short += " · docker " + l.Image
			sev = Medium
		} else if l.Process != "" {
			msg += " (" + l.Process + ")"
			if l.Unit != "" {
				short += " · " + l.Unit + ".service"
			}
		}
		if what, bad := riskyPorts[l.Port]; bad {
			msg += ", " + what
			short += " · " + what
			sev = High
		}
		var where []Location
		for _, s := range l.Sources {
			d := ""
			switch s {
			case "docker":
				d = l.Container
				if l.Image != "" {
					d += " (" + l.Image + ")"
				}
			case "proc":
				d = l.Process
				if l.PID != 0 {
					d += " pid " + strconv.Itoa(l.PID)
				}
				if l.Unit != "" {
					d += ", " + l.Unit + ".service"
				}
			}
			where = append(where, Location{Source: s, Detail: strings.TrimSpace(strings.Trim(d, ", "))})
		}
		c.add(Finding{
			Type: Unregistered, Severity: sev, Service: label, Port: l.Port,
			Message: msg, Where: where, Compact: true, Short: short,
			Fix: fmt.Sprintf("add port: %d to the registry, bind it to 127.0.0.1, or stop it", l.Port),
		})
	}
}

// The proxy and tunnel are described by the hosts they serve; listing their
// own ports as unregistered would be noise on every run.
func (c *checker) isOwnProxy(l discover.Listener) bool {
	hay := strings.ToLower(l.Process + " " + l.Container + " " + l.Image + " " + l.Unit)
	for key, src := range proxyNames {
		if strings.Contains(hay, key) && c.sourceHasSites(src) {
			return true
		}
	}
	return false
}

func (c *checker) sourceHasSites(name string) bool {
	for _, st := range c.in.Snap.Sources {
		if st.Name == name && st.State == "ok" && st.Count > 0 {
			return true
		}
	}
	return false
}

// A tunnel created in the Cloudflare dashboard keeps its routes there, not in a
// file, so cloudflared can run here while the cloudflared source finds nothing.
// Hostnames behind it are invisible, and a registry entry for one can read as DEAD.
func (c *checker) dashboardTunnel() {
	if c.sourceHasSites("cloudflared") {
		return
	}
	for _, l := range c.in.Snap.Listeners {
		if l.Process == "cloudflared" {
			c.rep.Notes = append(c.rep.Notes,
				"cloudflared is running but no config file with routes was found. Tunnels managed in the Cloudflare dashboard keep their hostnames there, so unlisted cannot see them and may report their registry entries as DEAD. Add ignore: true to those entries, or point --cloudflared at a config file")
			return
		}
	}
}

func (c *checker) certs() {
	for _, p := range c.in.Probes {
		if p.CertDays == nil {
			continue
		}
		svc := c.serviceByHost(p.Host)
		reg := Location{Source: "registry", File: c.in.Registry.Path, Line: svc.Line}
		d := *p.CertDays
		switch {
		case d < 0:
			c.add(Finding{Type: Cert, Severity: High, Service: svc.Label(), Host: p.Host,
				Message: fmt.Sprintf("certificate expired %d %s ago", -d, plural(-d, "day", "days")),
				Where:   []Location{reg}, Fix: "renew the certificate; check the ACME client or proxy logs"})
		case d < c.in.CertWarnDays:
			c.add(Finding{Type: Cert, Severity: Medium, Service: svc.Label(), Host: p.Host,
				Message: fmt.Sprintf("certificate expires in %d %s", d, plural(d, "day", "days")),
				Where:   []Location{reg}, Fix: "renewal should have happened by now; check the ACME client or proxy logs"})
		case p.CertErr != "":
			c.add(Finding{Type: Cert, Severity: Low, Service: svc.Label(), Host: p.Host,
				Message: "certificate does not verify: " + p.CertErr,
				Where:   []Location{reg}, Fix: "serve a certificate from a public CA that covers this hostname"})
		}
	}
}

func (c *checker) serviceByHost(h string) registry.Service {
	for _, s := range c.in.Registry.Services {
		if s.Host == h {
			return s
		}
	}
	return registry.Service{Name: h}
}

func sortFindings(fs []Finding) {
	order := map[Type]int{}
	for i, t := range Types {
		order[t] = i
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Type != b.Type {
			return order[a.Type] < order[b.Type]
		}
		if a.Compact != b.Compact {
			return !a.Compact
		}
		if a.Severity != b.Severity {
			return a.Severity.rank() > b.Severity.rank()
		}
		if a.Port != b.Port && a.Compact {
			return a.Port < b.Port
		}
		return strings.ToLower(a.Service) < strings.ToLower(b.Service)
	})
}

func (r Report) Counts() map[Type]int {
	m := map[Type]int{}
	for _, f := range r.Findings {
		m[f.Type]++
	}
	return m
}

func (r Report) Failing(failOn map[Type]bool) int {
	n := 0
	for _, f := range r.Findings {
		if failOn[f.Type] {
			n++
		}
	}
	return n
}

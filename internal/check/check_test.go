package check

import (
	"strings"
	"testing"

	"github.com/kd-011/unlisted/internal/discover"
	"github.com/kd-011/unlisted/internal/probe"
	"github.com/kd-011/unlisted/internal/registry"
)

func src(name string, n int) discover.Status {
	return discover.Status{Name: name, State: "ok", Count: n}
}

func reg(svcs ...registry.Service) *registry.Registry {
	for i := range svcs {
		svcs[i].Line = 10 + i*5
	}
	return &registry.Registry{Path: "registry.yml", Services: svcs}
}

func exp(source, host, origin string) discover.Exposure {
	return discover.Exposure{Source: source, Host: host, Origin: discover.ParseOrigin(origin), File: "/etc/" + source, Line: 3}
}

func listen(port int, addr, proc string) discover.Listener {
	return discover.Listener{Port: port, Addr: addr, Public: addr != "127.0.0.1", Process: proc, PID: 1, Sources: []string{"proc"}}
}

// snap builds a snapshot where the tunnel and /proc loaded.
func snap(es []discover.Exposure, ls ...discover.Listener) discover.Snapshot {
	return discover.Snapshot{Exposures: es, Listeners: ls, Sources: []discover.Status{src("cloudflared", len(es)), src("proc", len(ls))}}
}

func of(r Report, t Type) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Type == t {
			out = append(out, f)
		}
	}
	return out
}

func TestUnregisteredHostnameSeverity(t *testing.T) {
	noAuth := exp("cloudflared", "old.example.com", "http://localhost:8087")
	guarded := exp("caddy", "g.example.com", "localhost:3100")
	guarded.Auth, guarded.AuthBy = true, "forward_auth"
	static := exp("caddy", "s.example.com", "")
	r := Run(Input{Registry: reg(), Snap: snap([]discover.Exposure{noAuth, guarded, static})})
	got := map[string]Finding{}
	for _, f := range of(r, Unregistered) {
		got[f.Host] = f
	}
	if len(got) != 3 {
		t.Fatalf("want 3 unregistered, got %d", len(got))
	}
	if got["old.example.com"].Severity != High || !strings.Contains(got["old.example.com"].Message, "no auth detected") {
		t.Errorf("no-auth host: %+v", got["old.example.com"])
	}
	if got["g.example.com"].Severity != Medium || !strings.Contains(got["g.example.com"].Message, "forward_auth") {
		t.Errorf("guarded host: %+v", got["g.example.com"])
	}
	if got["s.example.com"].Severity != Medium {
		t.Errorf("static host should be medium: %+v", got["s.example.com"])
	}
	if f := got["old.example.com"]; len(f.Where) != 1 || f.Where[0].Line != 3 || f.Fix == "" {
		t.Errorf("where/fix missing: %+v", f)
	}
}

func TestRegisteredHostIsNotUnregistered(t *testing.T) {
	r := Run(Input{
		Registry: reg(registry.Service{Name: "A", Host: "a.example.com", Port: 8080, Auth: registry.AuthApp}),
		Snap:     snap([]discover.Exposure{exp("cloudflared", "a.example.com", "http://localhost:8080")}, listen(8080, "127.0.0.1", "app")),
	})
	if len(r.Findings) != 0 {
		t.Fatalf("expected clean, got %+v", r.Findings)
	}
}

func TestIgnoreSilencesEverything(t *testing.T) {
	r := Run(Input{
		Registry: reg(registry.Service{Name: "Scratch", Host: "x.example.com", Port: 9000, Ignore: true}),
		Snap:     snap([]discover.Exposure{exp("cloudflared", "x.example.com", "http://localhost:9999")}, listen(9000, "0.0.0.0", "py")),
	})
	if len(r.Findings) != 0 {
		t.Fatalf("ignored service produced %+v", r.Findings)
	}
}

func TestUnregisteredPort(t *testing.T) {
	ls := []discover.Listener{
		listen(22, "0.0.0.0", "sshd"),
		listen(6379, "0.0.0.0", "redis-server"),
		listen(5000, "127.0.0.1", "dev"), // loopback: not exposed
		{Port: 9000, Addr: "0.0.0.0", Public: true, Container: "portainer", Image: "portainer-ce", Sources: []string{"docker"}},
	}
	r := Run(Input{Registry: reg(registry.Service{Name: "SSH", Port: 22, Auth: registry.AuthApp}), Snap: snap(nil, ls...)})
	got := map[int]Finding{}
	for _, f := range of(r, Unregistered) {
		got[f.Port] = f
	}
	if len(got) != 2 {
		t.Fatalf("want redis and portainer only, got %+v", got)
	}
	if got[6379].Severity != High || !strings.Contains(got[6379].Message, "Redis") {
		t.Errorf("redis: %+v", got[6379])
	}
	if got[9000].Severity != Medium || !got[9000].Compact || got[9000].Short == "" {
		t.Errorf("docker publish: %+v", got[9000])
	}
}

func TestOriginPortFoldedIntoHostFinding(t *testing.T) {
	// The origin is open on 0.0.0.0 as well: one finding, with the extra fact.
	r := Run(Input{Registry: reg(), Snap: snap(
		[]discover.Exposure{exp("cloudflared", "a.example.com", "http://localhost:8087")},
		listen(8087, "0.0.0.0", "wiki"))})
	fs := of(r, Unregistered)
	if len(fs) != 1 || !strings.Contains(fs[0].Message, "also open on all interfaces") {
		t.Fatalf("got %+v", fs)
	}
}

func TestOwnProxyPortsAreNotReported(t *testing.T) {
	s := snap(nil, listen(80, "0.0.0.0", "caddy"), listen(443, "0.0.0.0", "caddy"))
	s.Sources = append(s.Sources, src("caddy", 4))
	if r := Run(Input{Registry: reg(), Snap: s}); len(r.Findings) != 0 {
		t.Fatalf("proxy ports reported: %+v", r.Findings)
	}
	// With no Caddy sites read, a process called caddy is just a process.
	s.Sources = s.Sources[:2]
	if r := Run(Input{Registry: reg(), Snap: s}); len(r.Findings) != 2 {
		t.Fatalf("want 2 without the caddy source, got %d", len(r.Findings))
	}
}

func TestDeadNoRule(t *testing.T) {
	r := Run(Input{
		Registry: reg(registry.Service{Name: "Gitea", Host: "git.example.com", Port: 3000, Auth: registry.AuthApp}),
		Snap:     snap([]discover.Exposure{exp("cloudflared", "other.example.com", "http://localhost:1")}),
	})
	d := of(r, Dead)
	if len(d) != 1 || !strings.Contains(d[0].Message, "no tunnel or proxy rule serves git.example.com") {
		t.Fatalf("got %+v", d)
	}
	if d[0].Where[0].Source != "registry" || d[0].Where[0].Line != 10 {
		t.Errorf("registry line missing: %+v", d[0].Where)
	}
}

func TestDeadOriginNotListening(t *testing.T) {
	r := Run(Input{
		Registry: reg(registry.Service{Name: "Mealie", Host: "m.example.com", Port: 9925, Auth: registry.AuthApp}),
		Snap:     snap([]discover.Exposure{exp("cloudflared", "m.example.com", "http://localhost:9925")}, listen(22, "0.0.0.0", "sshd")),
	})
	d := of(r, Dead)
	if len(d) != 1 || !strings.Contains(d[0].Message, "nothing is listening on port 9925") {
		t.Fatalf("got %+v", d)
	}
	// A remote origin cannot be judged from here, so it is never dead.
	r = Run(Input{
		Registry: reg(registry.Service{Name: "NAS", Host: "n.example.com", URL: "https://192.168.1.20:5001", Auth: registry.AuthApp}),
		Snap:     snap([]discover.Exposure{exp("cloudflared", "n.example.com", "https://192.168.1.20:5001")}),
	})
	if len(r.Findings) != 0 {
		t.Fatalf("remote origin flagged: %+v", r.Findings)
	}
}

func TestDeadPortOnly(t *testing.T) {
	r := Run(Input{
		Registry: reg(registry.Service{Name: "Thing", Port: 4242, Auth: registry.AuthApp}),
		Snap:     snap(nil, listen(22, "0.0.0.0", "sshd")),
	})
	if d := of(r, Dead); len(d) != 1 || !strings.Contains(d[0].Message, "port 4242") {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestDeadIsNotGuessedWithoutData(t *testing.T) {
	// No tunnel, no proxy, no /proc: nothing can be said about a host, and the
	// report must admit that instead of calling it dead.
	r := Run(Input{
		Registry: reg(registry.Service{Name: "A", Host: "a.example.com", Port: 80, Auth: registry.AuthApp}),
		Snap:     discover.Snapshot{Sources: []discover.Status{{Name: "cloudflared", State: "absent"}}},
	})
	if len(r.Findings) != 0 {
		t.Fatalf("dead guessed with no data: %+v", r.Findings)
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "1 registry service could not be checked") {
		t.Errorf("notes: %v", r.Notes)
	}
}

func TestNoAuth(t *testing.T) {
	es := []discover.Exposure{
		exp("cloudflared", "open.example.com", "http://localhost:1"),
		exp("cloudflared", "declared.example.com", "http://localhost:2"),
		exp("cloudflared", "accepted.example.com", "http://localhost:3"),
		exp("caddy", "proxied.example.com", "localhost:4"),
	}
	es[3].Auth, es[3].AuthBy = true, "basicauth"
	ls := []discover.Listener{listen(1, "127.0.0.1", "a"), listen(2, "127.0.0.1", "b"), listen(3, "127.0.0.1", "c"), listen(4, "127.0.0.1", "d")}
	r := Run(Input{
		Registry: reg(
			registry.Service{Name: "Open", Host: "open.example.com", Port: 1},
			registry.Service{Name: "Declared", Host: "declared.example.com", Port: 2, Auth: registry.AuthAccess},
			registry.Service{Name: "Accepted", Host: "accepted.example.com", Port: 3, Auth: registry.AuthNone},
			registry.Service{Name: "Proxied", Host: "proxied.example.com", Port: 4},
		),
		Snap: snap(es, ls...),
	})
	na := of(r, NoAuth)
	if len(na) != 1 || na[0].Service != "Open" {
		t.Fatalf("want only Open, got %+v", na)
	}
	if !strings.Contains(na[0].Message, "no auth detected") || strings.Contains(strings.ToLower(na[0].Message), "insecure") {
		t.Errorf("wording: %q", na[0].Message)
	}
}

func TestNoAuthSilencedByProbeHint(t *testing.T) {
	in := Input{
		Registry: reg(registry.Service{Name: "A", Host: "a.example.com", Port: 1}),
		Snap:     snap([]discover.Exposure{exp("cloudflared", "a.example.com", "http://localhost:1")}, listen(1, "127.0.0.1", "a")),
	}
	if n := len(of(Run(in), NoAuth)); n != 1 {
		t.Fatalf("baseline: %d", n)
	}
	in.ProbeRan = true
	in.Probes = []probe.Result{{Host: "a.example.com", Status: 302, AuthHint: "cloudflare-access"}}
	if n := len(of(Run(in), NoAuth)); n != 0 {
		t.Errorf("probe saw an Access redirect but NOAUTH remained")
	}
}

func TestDrift(t *testing.T) {
	r := Run(Input{
		Registry: reg(registry.Service{Name: "Paperless", Host: "d.example.com", Port: 8000, Auth: registry.AuthApp}),
		Snap:     snap([]discover.Exposure{exp("cloudflared", "d.example.com", "http://localhost:8010")}, listen(8010, "127.0.0.1", "p")),
	})
	d := of(r, Drift)
	if len(d) != 1 || !strings.Contains(d[0].Message, "registry says port 8000") || !strings.Contains(d[0].Fix, "8010") {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestDriftUsesProxyOriginNotTunnelHop(t *testing.T) {
	// Tunnel -> Caddy:80 -> app:3000. The registry port is the app's.
	es := []discover.Exposure{
		exp("cloudflared", "a.example.com", "http://localhost:80"),
		exp("caddy", "a.example.com", "localhost:3000"),
	}
	r := Run(Input{
		Registry: reg(registry.Service{Name: "A", Host: "a.example.com", Port: 3000, Auth: registry.AuthApp}),
		Snap:     snap(es, listen(3000, "127.0.0.1", "app"), listen(80, "0.0.0.0", "caddy")),
	})
	if len(of(r, Drift)) != 0 {
		t.Fatalf("tunnel hop caused drift: %+v", r.Findings)
	}
}

func TestDriftDockerContainerOrigin(t *testing.T) {
	// Caddy in the compose network names the container; the registry records
	// the host port that container publishes.
	es := []discover.Exposure{exp("caddy", "j.example.com", "jellyfin:8096")}
	ls := []discover.Listener{{Port: 8097, Addr: "127.0.0.1", Container: "jellyfin", ContainerPort: 8096, Sources: []string{"docker"}}}
	r := Run(Input{
		Registry: reg(registry.Service{Name: "J", Host: "j.example.com", Port: 8097, Auth: registry.AuthApp}),
		Snap:     snap(es, ls...),
	})
	if len(of(r, Drift)) != 0 || len(of(r, Dead)) != 0 {
		t.Fatalf("docker alias not honoured: %+v", r.Findings)
	}
}

func TestWildcards(t *testing.T) {
	es := []discover.Exposure{
		exp("cloudflared", "*.apps.example.com", "http://localhost:80"),
		exp("cloudflared", "tool.example.com", "http://localhost:81"),
	}
	ls := []discover.Listener{listen(80, "127.0.0.1", "c"), listen(81, "127.0.0.1", "d")}
	// A registry wildcard registers hosts beneath it; a registry host under an
	// exposure wildcard is served by it.
	r := Run(Input{
		Registry: reg(
			registry.Service{Name: "Apps", Host: "*.apps.example.com", Port: 80, Auth: registry.AuthApp},
			registry.Service{Name: "Tool", Host: "tool.example.com", Port: 81, Auth: registry.AuthApp},
			registry.Service{Name: "Blog", Host: "blog.apps.example.com", Auth: registry.AuthApp},
		),
		Snap: snap(es, ls...),
	})
	if len(r.Findings) != 0 {
		t.Fatalf("wildcards: %+v", r.Findings)
	}
	r = Run(Input{Registry: reg(registry.Service{Name: "Blog", Host: "blog.apps.example.com", Auth: registry.AuthApp}), Snap: snap(es[:1], ls...)})
	got := of(r, Unregistered)
	if len(got) != 1 || got[0].Host != "*.apps.example.com" {
		t.Fatalf("exposure wildcard should stay unregistered until declared: %+v", r.Findings)
	}
}

func TestCertFindings(t *testing.T) {
	d := func(n int) *int { return &n }
	in := Input{
		Registry: reg(
			registry.Service{Name: "Soon", Host: "soon.example.com", Auth: registry.AuthApp},
			registry.Service{Name: "Gone", Host: "gone.example.com", Auth: registry.AuthApp},
			registry.Service{Name: "Fine", Host: "fine.example.com", Auth: registry.AuthApp},
			registry.Service{Name: "Self", Host: "self.example.com", Auth: registry.AuthApp},
		),
		Snap:     snap(nil),
		ProbeRan: true,
		Probes: []probe.Result{
			{Host: "soon.example.com", Status: 200, CertDays: d(5)},
			{Host: "gone.example.com", Status: 200, CertDays: d(-3)},
			{Host: "fine.example.com", Status: 200, CertDays: d(80)},
			{Host: "self.example.com", Status: 200, CertDays: d(80), CertErr: "x509: certificate signed by unknown authority"},
		},
	}
	got := map[string]Finding{}
	for _, f := range of(Run(in), Cert) {
		got[f.Service] = f
	}
	if len(got) != 3 {
		t.Fatalf("want 3 cert findings, got %+v", got)
	}
	if got["Soon"].Severity != Medium || !strings.Contains(got["Soon"].Message, "5 days") {
		t.Errorf("soon: %+v", got["Soon"])
	}
	if got["Gone"].Severity != High || !strings.Contains(got["Gone"].Message, "expired 3 days ago") {
		t.Errorf("gone: %+v", got["Gone"])
	}
	if got["Self"].Severity != Low {
		t.Errorf("self: %+v", got["Self"])
	}
}

func TestDeadFromProbe(t *testing.T) {
	in := Input{
		Registry: reg(registry.Service{Name: "A", Host: "a.example.com", Auth: registry.AuthApp}),
		Snap:     snap([]discover.Exposure{exp("cloudflared", "a.example.com", "")}),
		ProbeRan: true,
		Probes:   []probe.Result{{Host: "a.example.com", Status: 502}},
	}
	d := of(Run(in), Dead)
	if len(d) != 1 || !strings.Contains(d[0].Message, "probe failed: HTTP 502") {
		t.Fatalf("got %+v", d)
	}
}

func TestSortOrder(t *testing.T) {
	es := []discover.Exposure{
		exp("cloudflared", "b.example.com", "http://localhost:1"),
		exp("cloudflared", "a.example.com", "http://localhost:2"),
	}
	es[1].Auth = true
	r := Run(Input{
		Registry: reg(registry.Service{Name: "Dead", Host: "dead.example.com", Port: 1, Auth: registry.AuthApp}),
		Snap:     snap(es, listen(9, "0.0.0.0", "x")),
	})
	var order []string
	for _, f := range r.Findings {
		order = append(order, string(f.Type)+":"+f.Service)
	}
	want := []string{"unregistered:b.example.com", "unregistered:a.example.com", "unregistered:x", "dead:Dead"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order\n got %v\nwant %v", order, want)
	}
}

func TestParseTypes(t *testing.T) {
	m, err := ParseTypes("dead, NoAuth")
	if err != nil || !m[Dead] || !m[NoAuth] || m[Drift] {
		t.Errorf("%v %v", m, err)
	}
	if m, _ := ParseTypes("all"); len(m) != len(Types) {
		t.Error("all")
	}
	if m, _ := ParseTypes("none"); len(m) != 0 {
		t.Error("none")
	}
	if _, err := ParseTypes("dead,bogus"); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("bad type: %v", err)
	}
}

package discover

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseOrigin(t *testing.T) {
	cases := []struct {
		in           string
		scheme, host string
		port         int
		local        bool
	}{
		{"http://localhost:8080", "http", "localhost", 8080, true},
		{"localhost:8080", "", "localhost", 8080, true},
		{":8080", "", "", 8080, true},
		{"http://127.0.0.1", "http", "127.0.0.1", 80, true},
		{"https://192.168.1.20:5001", "https", "192.168.1.20", 5001, false},
		{"https://nas.lan", "https", "nas.lan", 443, false},
		{"[::1]:3000", "", "::1", 3000, true},
		{"http://[::1]:3000/path", "http", "::1", 3000, true},
		{"ssh://localhost:2222", "ssh", "localhost", 2222, true},
		{"unix:/run/app.sock", "unix", "/run/app.sock", 0, true},
		{"http_status:404", "http_status", "", 0, false},
		{"jellyfin:8096", "", "jellyfin", 8096, false},
	}
	for _, c := range cases {
		o := ParseOrigin(c.in)
		if o.Scheme != c.scheme || o.Host != c.host || o.Port != c.port || o.Local != c.local {
			t.Errorf("%q -> %+v", c.in, o)
		}
	}
	if !ParseOrigin("").IsZero() {
		t.Error("empty origin should be zero")
	}
}

// Spellings taken from the Caddy, nginx and cloudflared docs for a backend that
// is a socket or a built-in service, not a TCP port.
func TestParseOriginSocketsAndBuiltIns(t *testing.T) {
	cases := []struct {
		in, scheme, host string
	}{
		{"unix//run/app.sock", "unix", "/run/app.sock"},
		{"http://unix:/tmp/backend.socket:/uri/", "unix", "/tmp/backend.socket"},
		{"unix:/run/app.sock", "unix", "/run/app.sock"},
		{"bastion", "bastion", ""},
		{"h2c://localhost:8081", "h2c", "localhost"},
	}
	for _, c := range cases {
		o := ParseOrigin(c.in)
		if o.Scheme != c.scheme || o.Host != c.host || o.Port != 0 && c.scheme != "h2c" {
			t.Errorf("%q -> %+v", c.in, o)
		}
		if c.scheme == "unix" && !o.Local {
			t.Errorf("%q should be local", c.in)
		}
	}
	if o := ParseOrigin("h2c://localhost:8081"); o.Port != 8081 || !o.Local {
		t.Errorf("h2c -> %+v", o)
	}
}

func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func byHost(es []Exposure) map[string]Exposure {
	m := map[string]Exposure{}
	for _, e := range es {
		m[e.Host] = e
	}
	return m
}

func TestParseCloudflared(t *testing.T) {
	res, err := ParseCloudflared(read(t, "parsers/cloudflared.yml"), "cf.yml")
	if err != nil {
		t.Fatal(err)
	}
	h := byHost(res.Exposures)
	if _, ok := h["blocked.example.com"]; ok {
		t.Error("http_status rules are not exposures")
	}
	if len(res.Exposures) != 6 {
		t.Errorf("want 6 exposures, got %d", len(res.Exposures))
	}
	if h["files.example.com"].Origin.Port != 8090 {
		t.Error("hostname should be lowercased and port read")
	}
	if e := h["app.example.com"]; e.Line != 6 || e.File != "cf.yml" || e.Source != "cloudflared" {
		t.Errorf("location wrong: %+v", e)
	}
	if !h["guarded.example.com"].Auth || h["app.example.com"].Auth {
		t.Error("originRequest.access should be the only auth signal")
	}
	if h["nas.example.com"].Origin.Local {
		t.Error("LAN origin is not local")
	}
	if h["*.wild.example.com"].Host == "" {
		t.Error("wildcard rule dropped")
	}
	if res.Count != 7 {
		t.Errorf("count should include blocked rule, got %d", res.Count)
	}
}

func TestParseCloudflaredBroken(t *testing.T) {
	if _, err := ParseCloudflared([]byte("ingress: [\n"), "x.yml"); err == nil {
		t.Error("expected a parse error")
	}
	if res, err := ParseCloudflared([]byte(""), "x.yml"); err != nil || len(res.Exposures) != 0 {
		t.Errorf("empty file: %v %v", res, err)
	}
}

func TestParseCaddyfile(t *testing.T) {
	res := ParseCaddyfile(read(t, "parsers/Caddyfile"), "Caddyfile")
	h := byHost(res.Exposures)

	if e := h["app.example.com"]; e.Origin.Port != 8080 || e.Auth {
		t.Errorf("app: %+v", e)
	}
	// Both addresses of a multi-address block, scheme and port stripped.
	one, two := h["one.example.com"], h["two.example.com"]
	if one.Host == "" || two.Host == "" {
		t.Fatalf("multi-address block lost a host: %v", h)
	}
	// The matcher-scoped upstream is skipped in favour of the first plain one
	// only when it has none; here the matcher form comes first and wins.
	if one.Origin.Port != 9000 {
		t.Errorf("matcher should be skipped, upstream read: %+v", one.Origin)
	}
	if e := h["secure.example.com"]; !e.Auth || e.AuthBy != "forward_auth" || e.Origin.Host != "10.0.0.5" {
		t.Errorf("auth via imported snippet not detected: %+v", e)
	}
	// basic_auth scoped to /admin/* leaves the rest of the site open.
	if e := h["basic.example.com"]; e.Auth || e.Origin.Port != 5000 {
		t.Errorf("path-scoped basic_auth must not count as site auth: %+v", e)
	}
	if e := h["wholesite.example.com"]; !e.Auth || e.AuthBy != "basic_auth" {
		t.Errorf("unscoped basic_auth should count: %+v", e)
	}
	if e := h["handled.example.com"]; e.Auth || e.Origin.Port != 5100 {
		t.Errorf("auth inside handle must not count, origin still read: %+v", e)
	}
	if e := h["named.example.com"]; e.Auth {
		t.Errorf("named-matcher auth must not count: %+v", e)
	}
	if e, ok := h["static.example.com"]; !ok || !e.Origin.IsZero() {
		t.Errorf("static site should be an exposure with no origin: %+v", e)
	}
	if _, ok := h["localhost"]; ok {
		t.Error("localhost is not public")
	}
	for host := range h {
		if strings.HasPrefix(host, ":") || strings.Contains(host, "{") {
			t.Errorf("port-only or placeholder site leaked: %q", host)
		}
	}
	if e := h["fallback.example.com"]; e.Host == "" {
		t.Error("env placeholder default should resolve")
	}
	if e := h["*.wild.example.com"]; e.Origin.Port != 7000 {
		t.Errorf("trailing comment broke the upstream: %+v", e)
	}
	if e := h["app.example.com"]; e.Line != 15 {
		t.Errorf("line = %d", e.Line)
	}
}

func TestParseCaddyfileBraceless(t *testing.T) {
	res := ParseCaddyfile(read(t, "parsers/Caddyfile.braceless"), "Caddyfile")
	if len(res.Exposures) != 1 {
		t.Fatalf("want one site, got %+v", res.Exposures)
	}
	e := res.Exposures[0]
	if e.Host != "single.example.com" || e.Origin.Port != 8080 || !e.Auth || e.AuthBy != "basic_auth" || e.Line != 2 {
		t.Errorf("braceless site: %+v", e)
	}
}

// A top-level import, a snippet and a global options block are not site
// addresses, whatever order they appear in.
func TestParseCaddyfileNeverMistakesDirectivesForSites(t *testing.T) {
	for _, name := range []string{"Caddyfile.import-top", "Caddyfile.snippet-global"} {
		res := ParseCaddyfile(read(t, "parsers/"+name), "Caddyfile")
		h := byHost(res.Exposures)
		if len(res.Exposures) != 2 {
			t.Fatalf("%s: want exactly 2 sites, got %+v", name, res.Exposures)
		}
		for host := range h {
			if !strings.HasSuffix(host, ".example.com") {
				t.Errorf("%s: fake site %q", name, host)
			}
		}
	}
	h := byHost(ParseCaddyfile(read(t, "parsers/Caddyfile.import-top"), "Caddyfile").Exposures)
	if h["one.example.com"].Origin.Port != 8001 || h["two.example.com"].Origin.Port != 8002 {
		t.Errorf("origins lost: %+v", h)
	}
	h = byHost(ParseCaddyfile(read(t, "parsers/Caddyfile.snippet-global"), "Caddyfile").Exposures)
	if !h["a.example.com"].Auth || h["b.example.com"].Auth {
		t.Errorf("snippet auth should reach only the importing site: %+v", h)
	}
}

// A bare first line is not enough for the single-site form: with braced sites
// anywhere in the file it is not a site at all.
func TestParseCaddyfileBareFirstLineWithBracedSites(t *testing.T) {
	res := ParseCaddyfile(read(t, "parsers/Caddyfile.bare-first"), "Caddyfile")
	h := byHost(res.Exposures)
	if len(res.Exposures) != 2 || h["one.example.com"].Origin.Port != 8001 || h["two.example.com"].Origin.Port != 8002 {
		t.Fatalf("want only the two braced sites, got %+v", res.Exposures)
	}
	if _, ok := h["bare.example.com"]; ok {
		t.Error("bare first line became a site")
	}
}

// A file that starts with any standard directive is never a braceless site.
func TestParseCaddyfileDirectiveFirstLineIsNotASite(t *testing.T) {
	for _, d := range []string{"log", "encode gzip", "header -Server", "skip_log", "vars foo bar", "map {host} {x}", "tracing"} {
		res := ParseCaddyfile([]byte(d+"\nsite.example.com {\n\treverse_proxy localhost:1\n}\n"), "Caddyfile")
		if len(res.Exposures) != 1 || res.Exposures[0].Host != "site.example.com" {
			t.Errorf("%q: got %+v", d, res.Exposures)
		}
	}
}

func TestParseNginx(t *testing.T) {
	es := ParseNginx(read(t, "parsers/nginx.conf"), "nginx.conf")
	h := byHost(es)

	// The redirect-only server and the proxy server share a name; keep the proxy.
	app := h["app.example.com"]
	if app.Origin.Port != 8080 {
		t.Errorf("app should keep the proxying server: %+v", app)
	}
	// auth_basic only inside /admin/ does not protect the host.
	if app.Auth {
		t.Error("auth on a sub-location must not count as host auth")
	}
	if www := h["www.app.example.com"]; www.Host == "" || !www.Origin.IsZero() {
		t.Errorf("redirect-only alias should be an exposure with no origin: %+v", www)
	}
	sec := h["secure.example.com"]
	if !sec.Auth || sec.AuthBy != "auth_request" || sec.Origin.Port != 9000 {
		t.Errorf("secure (upstream + auth_request): %+v", sec)
	}
	if h["off.example.com"].Auth {
		t.Error("auth_basic off is not auth")
	}
	for _, skip := range []string{"_", "dyn.example.com"} {
		if skip == "dyn.example.com" {
			if h[skip].Host == "" || !h[skip].Origin.IsZero() {
				t.Errorf("variable proxy_pass should give an exposure with no origin: %+v", h[skip])
			}
			continue
		}
		if _, ok := h[skip]; ok {
			t.Errorf("%q should be skipped", skip)
		}
	}
	for host := range h {
		if strings.HasPrefix(host, "~") {
			t.Errorf("regex server_name leaked: %q", host)
		}
	}
	if o := h["only-sub.example.com"].Origin; o.Port != 6000 {
		t.Errorf("non-root location proxy_pass is the fallback origin: %+v", o)
	}
	if app.Line == 0 || app.File != "nginx.conf" {
		t.Errorf("location missing: %+v", app)
	}
}

func TestParseProcNet(t *testing.T) {
	v4 := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0\n" +
		"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0 100 0 0 10 0\n" +
		"   2: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 333 1 0 100 0 0 10 0\n" +
		"garbage\n"
	socks := ParseProcNet([]byte(v4), false)
	if len(socks) != 3 {
		t.Fatalf("got %d sockets", len(socks))
	}
	if socks[0].port != 8080 || !socks[0].addr.IsLoopback() || !socks[0].listen {
		t.Errorf("loopback: %+v", socks[0])
	}
	if socks[1].port != 22 || !socks[1].addr.IsUnspecified() {
		t.Errorf("wildcard: %+v", socks[1])
	}
	if socks[2].listen {
		t.Error("established connection counted as listening")
	}

	v6 := "  sl\n   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 444 1\n" +
		"   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 555 1\n" +
		"   2: 0000000000000000FFFF00000100007F:0035 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 666 1\n"
	s6 := ParseProcNet([]byte(v6), true)
	if len(s6) != 3 {
		t.Fatalf("got %d v6 sockets", len(s6))
	}
	if !s6[0].addr.IsLoopback() || s6[0].port != 80 {
		t.Errorf("::1 not parsed: %+v", s6[0])
	}
	if !s6[1].addr.IsUnspecified() || s6[1].port != 443 {
		t.Errorf(":: not parsed: %+v", s6[1])
	}
	if !s6[2].addr.IsLoopback() || s6[2].addr.To4() == nil {
		t.Errorf("v4-mapped should become v4: %+v", s6[2])
	}
}

func TestProcFixtureMapsProcesses(t *testing.T) {
	env := Env{Root: filepath.Join("..", "..", "testdata", "root")}
	res, err := Proc{}.Discover(env)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]Listener{}
	for _, l := range res.Listeners {
		got[l.Port] = l
	}
	if got[22].Process != "sshd" || !got[22].Public {
		t.Errorf("sshd: %+v", got[22])
	}
	if got[8080].Process != "app" || got[8080].Public {
		t.Errorf("loopback app: %+v", got[8080])
	}
	if got[22].PID == 0 {
		t.Error("pid not attributed")
	}
}

func TestInterpreterNames(t *testing.T) {
	env := Env{Root: filepath.Join("..", "..", "demo")}
	res, err := Proc{}.Discover(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range res.Listeners {
		if l.Port == 8765 && l.Process != "python3 http.server" {
			t.Errorf("python module name = %q", l.Process)
		}
		if l.Port == 3001 && l.Process != "node server.js" {
			t.Errorf("node script name = %q", l.Process)
		}
	}
}

func TestParseDocker(t *testing.T) {
	body := `[
 {"Names":["/redis"],"Image":"redis:7","Ports":[
   {"IP":"0.0.0.0","PrivatePort":6379,"PublicPort":6379,"Type":"tcp"},
   {"IP":"::","PrivatePort":6379,"PublicPort":6379,"Type":"tcp"}]},
 {"Names":["/web"],"Image":"nginx","Ports":[
   {"IP":"127.0.0.1","PrivatePort":80,"PublicPort":8081,"Type":"tcp"},
   {"PrivatePort":443,"Type":"tcp"},
   {"IP":"0.0.0.0","PrivatePort":53,"PublicPort":53,"Type":"udp"}]}
]`
	res, err := ParseDocker([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 2 {
		t.Errorf("containers = %d", res.Count)
	}
	var pub, loop int
	for _, l := range res.Listeners {
		if l.Public {
			pub++
		} else {
			loop++
		}
		if l.Container == "" || l.ContainerPort == 0 {
			t.Errorf("missing container info: %+v", l)
		}
	}
	// Unpublished and UDP ports are not listeners; both redis binds are.
	if pub != 2 || loop != 1 {
		t.Errorf("public=%d loopback=%d", pub, loop)
	}
	if _, err := ParseDocker([]byte("not json")); err == nil {
		t.Error("expected error on junk")
	}
}

func TestDockerSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("cannot create unix socket here:", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`[{"Names":["/db"],"Image":"postgres","Ports":[{"IP":"0.0.0.0","PrivatePort":5432,"PublicPort":5432,"Type":"tcp"}]}]`))
	})}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	res, err := Docker{}.Discover(Env{DockerSock: sock})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Listeners) != 1 || res.Listeners[0].Container != "db" || res.Listeners[0].Port != 5432 {
		t.Errorf("got %+v", res.Listeners)
	}
}

func TestParseSystemctl(t *testing.T) {
	out := "ssh.service loaded active running OpenBSD Secure Shell server\n" +
		"cron.service loaded active running Regular background program processing daemon\n" +
		"not-a-service.timer loaded active waiting x\n\n"
	u := ParseSystemctl([]byte(out))
	if len(u) != 2 || u["ssh.service"] != "OpenBSD Secure Shell server" {
		t.Errorf("got %v", u)
	}
}

func TestSystemdUnitAttribution(t *testing.T) {
	res := Run(Env{Root: filepath.Join("..", "..", "demo")}, AllSources())
	for _, l := range res.Listeners {
		if l.Port == 22 && l.Unit != "ssh" {
			t.Errorf("sshd unit = %q", l.Unit)
		}
		if l.Port == 8096 && l.Container != "jellyfin" {
			t.Errorf("docker and proc listeners should merge, got %+v", l)
		}
	}
}

// Every source must degrade, so an empty machine is a normal input.
func TestRunDegradesGracefully(t *testing.T) {
	snap := Run(Env{Root: t.TempDir()}, AllSources())
	if len(snap.Sources) != 6 {
		t.Fatalf("sources: %d", len(snap.Sources))
	}
	for _, s := range snap.Sources {
		if s.State != "absent" {
			t.Errorf("%s = %s, want absent", s.Name, s.State)
		}
	}
	if len(snap.Exposures)+len(snap.Listeners) != 0 {
		t.Error("nothing should be found in an empty root")
	}
}

func TestRunBrokenSourceDoesNotStopOthers(t *testing.T) {
	root := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(body), 0o644)
	}
	must("etc/cloudflared/config.yml", "ingress: [\n")
	must("etc/caddy/Caddyfile", "ok.example.com {\n\treverse_proxy localhost:1\n}\n")
	snap := Run(Env{Root: root}, AllSources())
	states := map[string]string{}
	for _, s := range snap.Sources {
		states[s.Name] = s.State
	}
	if states["cloudflared"] != "error" || states["caddy"] != "ok" {
		t.Errorf("states: %v", states)
	}
	if len(snap.Exposures) != 1 {
		t.Errorf("caddy result lost: %v", snap.Exposures)
	}
}

func TestSkipAndExplicitPaths(t *testing.T) {
	dir := t.TempDir()
	cf := filepath.Join(dir, "tunnel.yml")
	os.WriteFile(cf, []byte("ingress:\n  - hostname: a.example.com\n    service: http://localhost:1\n"), 0o644)
	env := Env{Cloudflared: cf, Skip: ParseSkip("proc, Docker,systemd"), Root: t.TempDir()}
	snap := Run(env, AllSources())
	if len(snap.Exposures) != 1 {
		t.Fatalf("explicit path ignored: %v", snap.Exposures)
	}
	for _, s := range snap.Sources {
		if (s.Name == "proc" || s.Name == "docker") && s.State != "skipped" {
			t.Errorf("%s not skipped", s.Name)
		}
	}
	if snap.Exposures[0].File != cf {
		t.Errorf("explicit path should be shown as given: %q", snap.Exposures[0].File)
	}
}

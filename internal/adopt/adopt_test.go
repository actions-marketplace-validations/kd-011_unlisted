package adopt

import (
	"strings"
	"testing"

	"github.com/kd-011/unlisted/internal/discover"
	"github.com/kd-011/unlisted/internal/registry"
)

func TestTitleFromHost(t *testing.T) {
	for in, want := range map[string]string{
		"jellyfin.example.com": "Jellyfin",
		"home-assistant.x.org": "Home assistant",
		"*.apps.example.com":   "Apps (wildcard)",
		"localhosty":           "Localhosty",
	} {
		if got := titleFromHost(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestBuildProducesValidRegistry(t *testing.T) {
	snap := discover.Snapshot{
		Exposures: []discover.Exposure{
			{Source: "cloudflared", Host: "*.apps.example.com", Origin: discover.ParseOrigin("http://localhost:80")},
			{Source: "caddy", Host: "a.example.com", Origin: discover.ParseOrigin("localhost:3000"), Auth: true, AuthBy: "forward_auth"},
			{Source: "caddy", Host: "static.example.com"},
		},
		Listeners: []discover.Listener{
			{Port: 3000, Addr: "127.0.0.1"},
			{Port: 6379, Addr: "0.0.0.0", Public: true, Container: "redis"},
			{Port: 6380, Addr: "0.0.0.0", Public: true, Container: "redis"},
		},
		Sources: []discover.Status{{Name: "proc", State: "ok", Count: 3}},
	}
	res := Build(snap)
	reg, err := registry.Parse([]byte(res.YAML), "init.yml")
	if err != nil {
		t.Fatalf("generated registry does not parse: %v\n%s", err, res.YAML)
	}
	if res.Hosts != 3 || res.Ports != 2 || len(reg.Services) != 5 {
		t.Errorf("hosts %d ports %d services %d\n%s", res.Hosts, res.Ports, len(reg.Services), res.YAML)
	}
	names := map[string]bool{}
	for _, s := range reg.Services {
		if names[s.Name] {
			t.Errorf("duplicate name %q", s.Name)
		}
		names[s.Name] = true
	}
	// Nothing was listening on :80, so the wildcard is written but silenced.
	if len(res.Ignored) != 1 || !strings.Contains(res.Ignored[0], "*.apps.example.com") {
		t.Errorf("ignored: %v", res.Ignored)
	}
}

func TestBuildEmpty(t *testing.T) {
	reg, err := registry.Parse([]byte(Build(discover.Snapshot{}).YAML), "init.yml")
	if err != nil || len(reg.Services) != 0 {
		t.Fatalf("%v %v", reg, err)
	}
}

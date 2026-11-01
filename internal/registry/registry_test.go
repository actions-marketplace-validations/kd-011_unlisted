package registry

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	src := `services:
  - name: Jellyfin
    host: Jellyfin.Example.com.
    port: 8096
    auth: app
    owner: media
  - name: NAS
    host: nas.example.com
    url: https://192.168.1.20:5001
  - name: Scratch
    port: 9999
    ignore: true
`
	reg, err := Parse([]byte(src), "r.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Services) != 3 {
		t.Fatalf("got %d services", len(reg.Services))
	}
	j := reg.Services[0]
	if j.Host != "jellyfin.example.com" {
		t.Errorf("host not normalised: %q", j.Host)
	}
	if j.Line != 2 || reg.Services[1].Line != 7 {
		t.Errorf("lines wrong: %d %d", j.Line, reg.Services[1].Line)
	}
	if got := reg.Services[1].EffectivePort(); got != 5001 {
		t.Errorf("port from url = %d", got)
	}
	if !reg.Services[2].Ignore {
		t.Error("ignore not read")
	}
}

func TestEffectivePortDefaults(t *testing.T) {
	for url, want := range map[string]int{
		"https://x.lan": 443, "http://x.lan": 80, "http://x.lan:81": 81, "": 0,
	} {
		if got := (Service{URL: url}).EffectivePort(); got != want {
			t.Errorf("%q -> %d, want %d", url, got, want)
		}
	}
	if got := (Service{Port: 7, URL: "http://x:9"}).EffectivePort(); got != 7 {
		t.Errorf("explicit port must win, got %d", got)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"typo suggests field", "services:\n  - name: A\n    host: a.example.com\n    prot: 80\n", `did you mean "port"`},
		{"unknown field", "services:\n  - name: A\n    host: a.example.com\n    colour: red\n", "unknown field"},
		{"bad auth", "services:\n  - name: A\n    host: a.example.com\n    auth: magic\n", `auth "magic"`},
		{"no name", "services:\n  - host: a.example.com\n", "no name"},
		{"scheme in host", "services:\n  - name: A\n    host: https://a.example.com\n", "bare hostname"},
		{"nothing to check", "services:\n  - name: A\n", "at least one of host, port or url"},
		{"port range", "services:\n  - name: A\n    port: 70000\n", "out of range"},
		{"bad url", "services:\n  - name: A\n    url: localhost\n", "not an absolute URL"},
		{"duplicate host", "services:\n  - name: A\n    host: a.example.com\n  - name: B\n    host: a.example.com\n", "already declared on line 2"},
		{"top-level key", "sites:\n  - name: A\n", "unknown top-level key"},
		{"not a list", "services: nope\n", "must be a list"},
		{"port not a number", "services:\n  - name: A\n    port: abc\n", "r.yml:2"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.src), "r.yml")
		if err == nil {
			t.Errorf("%s: expected an error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q lacks %q", c.name, err, c.want)
		}
		if !strings.Contains(err.Error(), "r.yml:") {
			t.Errorf("%s: error has no file:line: %q", c.name, err)
		}
	}
}

func TestParseReportsEveryProblem(t *testing.T) {
	_, err := Parse([]byte("services:\n  - host: a.example.com\n  - name: B\n    auth: x\n    host: b.example.com\n"), "r.yml")
	if err == nil || !strings.Contains(err.Error(), "no name") || !strings.Contains(err.Error(), `auth "x"`) {
		t.Fatalf("want both problems, got %v", err)
	}
}

func TestEmptyRegistries(t *testing.T) {
	for _, src := range []string{"", "services:\n", "services: []\n"} {
		reg, err := Parse([]byte(src), "r.yml")
		if err != nil || len(reg.Services) != 0 {
			t.Errorf("%q: %v %v", src, reg, err)
		}
	}
}

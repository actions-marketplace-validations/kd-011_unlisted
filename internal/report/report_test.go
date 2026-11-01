package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kd-011/unlisted/internal/check"
	"github.com/kd-011/unlisted/internal/discover"
	"github.com/kd-011/unlisted/internal/probe"
)

func TestDetectColor(t *testing.T) {
	t.Setenv("TERM", "xterm")
	t.Setenv("NO_COLOR", "")
	unset := func() { t.Setenv("NO_COLOR", "") }
	_ = unset
	cases := []struct {
		name            string
		flag, tty       bool
		noColor, forced string
		term            string
		want            bool
	}{
		{"tty", false, true, "", "", "xterm", true},
		{"pipe", false, false, "", "", "xterm", false},
		{"flag wins", true, true, "", "", "xterm", false},
		{"forced on a pipe", false, false, "", "1", "xterm", true},
		{"dumb", false, true, "", "", "dumb", false},
	}
	for _, c := range cases {
		t.Setenv("CLICOLOR_FORCE", c.forced)
		t.Setenv("TERM", c.term)
		if got := DetectColor(c.flag, c.tty); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR_FORCE", "1")
	if DetectColor(false, true) {
		t.Error("NO_COLOR must beat everything but the flag")
	}
}

func clean() check.Report {
	return check.Report{Registry: "registry.yml", Services: 1,
		Sources: []discover.Status{{Name: "caddy", State: "ok", Count: 2, Unit: "sites"}, {Name: "docker", State: "absent"}}}
}

func TestTextCleanAndErrorSource(t *testing.T) {
	r := clean()
	r.Sources = append(r.Sources, discover.Status{Name: "nginx", State: "error", Detail: "/etc/nginx: permission denied"})
	var b bytes.Buffer
	Text(&b, r, Style{})
	out := b.String()
	for _, want := range []string{"Nothing unlisted.", "1 service declared", "caddy 2 sites", "docker absent", "nginx: /etc/nginx: permission denied"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestTextProbeBlockAligns(t *testing.T) {
	d := 12
	r := clean()
	r.ProbeRan = true
	r.Probes = []probe.Result{
		{Host: "a.example.com", Status: 200, CertDays: &d},
		{Host: "b.example.com", Err: "timed out"},
	}
	for _, st := range []Style{{}, {Color: true}} {
		var b bytes.Buffer
		Text(&b, r, st)
		if !strings.Contains(b.String(), "PROBE") || !strings.Contains(b.String(), "cert 12d") || !strings.Contains(b.String(), "timed out") {
			t.Errorf("probe block incomplete (color=%v):\n%s", st.Color, b.String())
		}
	}
}

func TestTextNotesAndSingular(t *testing.T) {
	r := clean()
	r.Notes = []string{"1 registry service could not be checked for DEAD: no data"}
	r.Findings = []check.Finding{{Type: check.Dead, Severity: check.Medium, Service: "A", Message: "m", Fix: "f", Where: []check.Location{{Source: "registry", File: "r.yml", Line: 3}}}}
	var b bytes.Buffer
	Text(&b, r, Style{})
	out := b.String()
	if !strings.Contains(out, "1 finding ") && !strings.HasSuffix(strings.TrimSpace(out), "1 dead") {
		t.Errorf("summary:\n%s", out)
	}
	if !strings.Contains(out, "note") || !strings.Contains(out, "r.yml:3") {
		t.Errorf("note or location missing:\n%s", out)
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	r := clean()
	r.Findings = []check.Finding{{Type: check.NoAuth, Severity: check.Medium, Service: "A", Message: "x | y", Fix: "auth: proxy|app"}}
	var b bytes.Buffer
	Markdown(&b, r)
	if !strings.Contains(b.String(), `x \| y`) || !strings.Contains(b.String(), `proxy\|app`) {
		t.Errorf("pipes not escaped:\n%s", b.String())
	}
}

func TestBuildJSONCountsAndFailOn(t *testing.T) {
	r := clean()
	r.Findings = []check.Finding{
		{Type: check.Dead, Severity: check.Medium},
		{Type: check.Drift, Severity: check.Low},
	}
	j := BuildJSON(r, "v9", map[check.Type]bool{check.Dead: true}, 1)
	if j.Summary.Total != 2 || j.Summary.Failing != 1 || j.Summary.ByType["drift"] != 1 || j.Summary.ByType["cert"] != 0 {
		t.Errorf("%+v", j.Summary)
	}
	if j.Summary.BySeverity["high"] != 0 || j.Summary.BySeverity["low"] != 1 {
		t.Errorf("%+v", j.Summary.BySeverity)
	}
	if j.Findings[0].Where == nil || j.Probes != nil {
		t.Error("where must be non-nil and probes absent when not run")
	}
}

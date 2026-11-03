package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// inRepo runs the test from the repository root so fixture paths in output
// match what a user typing the README commands would see.
func inRepo(t *testing.T) {
	t.Helper()
	old, _ := os.Getwd()
	if err := os.Chdir(filepath.Join("..", "..")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	t.Setenv("NO_COLOR", "")
	os.Unsetenv("NO_COLOR")
	t.Setenv("UNLISTED_ROOT", "")
	t.Setenv("CLICOLOR_FORCE", "")
}

func run(args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = Run(args, &o, &e)
	return code, o.String(), e.String()
}

var demo = []string{"check", "-f", "demo/registry.yml", "--config-root", "demo"}

func with(base []string, extra ...string) []string {
	return append(append([]string{}, base...), extra...)
}

func TestExitCodes(t *testing.T) {
	inRepo(t)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"findings", demo, ExitFindings},
		{"default command is check", []string{"-f", "demo/registry.yml", "--config-root", "demo"}, ExitFindings},
		{"clean", []string{"check", "-f", "testdata/clean.yml", "--config-root", "testdata/root"}, ExitClean},
		{"fail-on none", with(demo, "--fail-on", "none"), ExitClean},
		{"fail-on a type that is present", with(demo, "--fail-on", "drift"), ExitFindings},
		{"fail-on a type that is absent", with(demo, "--fail-on", "cert"), ExitClean},
		{"missing registry", []string{"check", "-f", "nope.yml"}, ExitError},
		{"bad flag", []string{"check", "--bogus"}, ExitError},
		{"bad fail-on", with(demo, "--fail-on", "weird"), ExitError},
		{"bad format", with(demo, "--format", "xml"), ExitError},
		{"unknown command", []string{"frobnicate"}, ExitError},
		{"stray argument", with(demo, "extra"), ExitError},
		{"version", []string{"version"}, ExitClean},
		{"help", []string{"help"}, ExitClean},
		{"-h", []string{"check", "-h"}, ExitClean},
	}
	for _, c := range cases {
		if code, _, errOut := run(c.args...); code != c.want {
			t.Errorf("%s: exit %d, want %d (stderr: %s)", c.name, code, c.want, errOut)
		}
	}
}

func TestBadRegistryIsExit2WithLine(t *testing.T) {
	inRepo(t)
	p := filepath.Join(t.TempDir(), "r.yml")
	os.WriteFile(p, []byte("services:\n  - name: A\n    prot: 1\n"), 0o644)
	code, _, errOut := run("check", "-f", p)
	if code != ExitError || !strings.Contains(errOut, "r.yml:3") || !strings.Contains(errOut, `"port"`) {
		t.Errorf("code %d stderr %q", code, errOut)
	}
}

func TestMissingRegistryHintsAtInit(t *testing.T) {
	inRepo(t)
	_, _, errOut := run("check", "-f", "nope.yml")
	if !strings.Contains(errOut, "unlisted init") {
		t.Errorf("stderr: %q", errOut)
	}
}

// The text report is the launch screenshot. The committed copy must match the
// code, or the README is lying about what the tool prints.
func TestDemoReportMatchesDocs(t *testing.T) {
	inRepo(t)
	code, out, _ := run(with(demo, "--no-color")...)
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile("docs/demo.txt", []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("docs/demo.txt")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Errorf("docs/demo.txt is stale; regenerate with UPDATE_GOLDEN=1 go test ./internal/cli -run Demo\n--- got ---\n%s", out)
	}
}

func TestDemoHasEveryFindingType(t *testing.T) {
	inRepo(t)
	_, out, _ := run(with(demo, "--no-color")...)
	for _, h := range []string{"UNREGISTERED", "DEAD", "NOAUTH", "DRIFT"} {
		if !strings.Contains(out, h) {
			t.Errorf("demo report lacks %s", h)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("--no-color emitted escape codes")
	}
	if strings.Contains(strings.ToLower(out), "insecure") {
		t.Error("report must say 'no auth detected', never 'insecure'")
	}
}

func TestColorRules(t *testing.T) {
	inRepo(t)
	// Not a terminal: plain by default.
	if _, out, _ := run(demo...); strings.Contains(out, "\x1b") {
		t.Error("colour emitted to a non-TTY")
	}
	t.Setenv("CLICOLOR_FORCE", "1")
	if _, out, _ := run(demo...); !strings.Contains(out, "\x1b[") {
		t.Error("CLICOLOR_FORCE ignored")
	}
	t.Setenv("NO_COLOR", "1")
	if _, out, _ := run(demo...); strings.Contains(out, "\x1b") {
		t.Error("NO_COLOR ignored")
	}
}

func TestConfigRootFromEnv(t *testing.T) {
	inRepo(t)
	t.Setenv("UNLISTED_ROOT", "demo")
	code, _, _ := run("check", "-f", "demo/registry.yml")
	if code != ExitFindings {
		t.Errorf("UNLISTED_ROOT not honoured, exit %d", code)
	}
}

func TestJSONSchema(t *testing.T) {
	inRepo(t)
	code, out, _ := run(with(demo, "--json")...)
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	for _, k := range []string{"schema", "version", "registry", "services", "sources", "summary", "findings", "notes"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}
	if doc["schema"] != "unlisted/v1" {
		t.Errorf("schema = %v", doc["schema"])
	}
	if _, ok := doc["probes"]; ok {
		t.Error("probes must be absent without --probe")
	}
	sum := doc["summary"].(map[string]any)
	if sum["total"].(float64) != 15 || sum["exit_code"].(float64) != 1 || sum["failing"].(float64) != 15 {
		t.Errorf("summary: %v", sum)
	}
	byType := sum["by_type"].(map[string]any)
	for _, k := range []string{"unregistered", "dead", "noauth", "drift", "cert"} {
		if _, ok := byType[k]; !ok {
			t.Errorf("by_type lacks %q", k)
		}
	}
	if byType["unregistered"].(float64) != 9 || byType["dead"].(float64) != 2 ||
		byType["noauth"].(float64) != 2 || byType["drift"].(float64) != 2 {
		t.Errorf("by_type: %v", byType)
	}
	if len(sum["fail_on"].([]any)) != 5 {
		t.Errorf("fail_on: %v", sum["fail_on"])
	}
	for _, raw := range doc["findings"].([]any) {
		f := raw.(map[string]any)
		for _, k := range []string{"type", "severity", "service", "message", "where", "fix"} {
			if _, ok := f[k]; !ok {
				t.Errorf("finding lacks %q: %v", k, f)
			}
		}
		if _, ok := f["where"].([]any); !ok {
			t.Errorf("where must be an array: %v", f["where"])
		}
	}
	// A source that was never on the box is still listed, with its state.
	for _, raw := range doc["sources"].([]any) {
		s := raw.(map[string]any)
		if s["name"] == "" || s["state"] == "" {
			t.Errorf("source: %v", s)
		}
	}
}

func TestJSONCleanRunHasEmptyArraysNotNull(t *testing.T) {
	inRepo(t)
	code, out, _ := run("check", "-f", "testdata/clean.yml", "--config-root", "testdata/root", "--json")
	if code != ExitClean {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, `"findings": []`) || !strings.Contains(out, `"notes": []`) {
		t.Errorf("empty collections must be [], got:\n%s", out)
	}
	if strings.Contains(out, "null") {
		t.Errorf("JSON contains null:\n%s", out)
	}
}

func TestJSONExitCodeFollowsFailOn(t *testing.T) {
	inRepo(t)
	_, out, _ := run(with(demo, "--json", "--fail-on", "cert")...)
	var doc struct {
		Summary struct{ ExitCode, Total, Failing int }
	}
	json.Unmarshal([]byte(out), &doc)
	if doc.Summary.ExitCode != 0 || doc.Summary.Failing != 0 || doc.Summary.Total != 15 {
		t.Errorf("%+v", doc.Summary)
	}
}

func TestMarkdown(t *testing.T) {
	inRepo(t)
	code, out, _ := run(with(demo, "--format", "markdown")...)
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"## unlisted report", "### UNREGISTERED (9)", "### DRIFT (2)", "| Severity | Service |", "**15 findings**"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("markdown has escape codes")
	}
}

func TestInitRoundTrip(t *testing.T) {
	inRepo(t)
	for _, root := range []string{"testdata/root", "demo"} {
		dir := t.TempDir()
		out := filepath.Join(dir, "registry.yml")
		code, stdout, errOut := run("init", "--config-root", root, "-o", out)
		if code != ExitClean {
			t.Fatalf("%s: init exit %d: %s", root, code, errOut)
		}
		if !strings.Contains(stdout, "wrote") || !strings.Contains(stdout, "next: unlisted check") {
			t.Errorf("%s: init output: %q", root, stdout)
		}
		code, report, _ := run("check", "-f", out, "--config-root", root, "--no-color")
		if code != ExitClean {
			t.Errorf("%s: adopted registry does not check clean:\n%s", root, report)
		}
	}
}

func TestInitStdoutAndNoOverwrite(t *testing.T) {
	inRepo(t)
	code, out, _ := run("init", "--config-root", "testdata/root", "-o", "-")
	if code != ExitClean || !strings.HasPrefix(out, "# unlisted registry") || !strings.Contains(out, "host: app.example.com") {
		t.Errorf("stdout init: %d %q", code, out)
	}

	p := filepath.Join(t.TempDir(), "registry.yml")
	os.WriteFile(p, []byte("keep me"), 0o644)
	if code, _, errOut := run("init", "--config-root", "testdata/root", "-o", p); code != ExitError || !strings.Contains(errOut, "--force") {
		t.Errorf("overwrite not refused: %d %q", code, errOut)
	}
	if b, _ := os.ReadFile(p); string(b) != "keep me" {
		t.Error("existing file modified")
	}
	if code, _, _ := run("init", "--config-root", "testdata/root", "-o", p, "--force"); code != ExitClean {
		t.Error("--force failed")
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "services:") {
		t.Error("--force did not write")
	}
}

func TestInitFlagsLowRiskDecisions(t *testing.T) {
	inRepo(t)
	_, out, _ := run("init", "--config-root", "demo", "-o", filepath.Join(t.TempDir(), "r.yml"))
	if !strings.Contains(out, "marked ignore: recipes.example.com") && !strings.Contains(out, "marked ignore: test.example.com") {
		t.Errorf("dead origins not called out:\n%s", out)
	}
	if !strings.Contains(out, "auth: none because no auth was detected") {
		t.Errorf("auth caveat missing:\n%s", out)
	}
}

func TestVersion(t *testing.T) {
	_, out, _ := run("version")
	if !strings.HasPrefix(out, "unlisted ") {
		t.Errorf("version output %q", out)
	}
}

func TestCheckNeverWrites(t *testing.T) {
	inRepo(t)
	before := snapshotTree(t, "demo")
	run(demo...)
	run(with(demo, "--json")...)
	after := snapshotTree(t, "demo")
	if before != after {
		t.Error("check modified the fixture tree")
	}
}

func snapshotTree(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			b.WriteString(p + info.ModTime().String() + "\n")
		}
		return nil
	})
	return b.String()
}

// A registry with no hostnames gives --probe nothing to contact, so this runs
// the probe path with no network at all.
func TestProbeWithNoHostsTouchesNothing(t *testing.T) {
	inRepo(t)
	p := filepath.Join(t.TempDir(), "r.yml")
	os.WriteFile(p, []byte("services:\n  - name: SSH\n    port: 22\n    auth: app\n"), 0o644)
	_, out, _ := run("check", "-f", p, "--config-root", "testdata/root", "--probe", "--json")
	if !strings.Contains(out, `"probes": []`) {
		t.Errorf("probes should be present and empty:\n%s", out)
	}
}

// chdir moves into dir for the test (testing.T.Chdir needs a newer Go than go.mod).
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

// A stranger who ran go install has no checkout, so the demo has to be inside
// the binary.
func TestDemoCommandNeedsNoFiles(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	chdir(t, t.TempDir())
	code, out, errOut := run("demo", "--no-color")
	if code != ExitClean {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
	for _, want := range []string{"UNREGISTERED", "DEAD", "NOAUTH", "DRIFT", "example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("demo output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, tmp) {
		t.Errorf("demo output leaks its temp directory:\n%s", out)
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Errorf("demo left %d entries in its temp directory", len(entries))
	}
}

// The default registry.yml missing is the first run for everyone. It should
// show what the machine exposes instead of an error.
func TestNoRegistryShowsWhatIsExposed(t *testing.T) {
	inRepo(t)
	root, _ := filepath.Abs("demo")
	chdir(t, t.TempDir())

	code, out, errOut := run("check", "--config-root", root, "--no-color")
	if code != ExitFindings || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{"No registry.yml", "unlisted init", "UNREGISTERED", "jellyfin.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	_, js, _ := run("check", "--config-root", root, "--json")
	var got struct {
		Notes []string `json:"notes"`
	}
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Notes) == 0 || !strings.Contains(got.Notes[0], "No registry.yml") {
		t.Errorf("json notes: %q", got.Notes)
	}

	// Naming a file that is missing is still a mistake worth failing on.
	if code, _, _ := run("check", "-f", "registry.yml", "--config-root", root); code != ExitError {
		t.Errorf("explicit -f with a missing file: exit %d, want %d", code, ExitError)
	}
}

// Config written the way the Caddy, nginx, cloudflared and Docker docs write
// it: sockets, built-in services, includes that match nothing, wildcard sites.
func TestDocumentationShapes(t *testing.T) {
	inRepo(t)
	code, js, errOut := run("check", "--config-root", "testdata/docshapes", "--skip", "proc,systemd", "--json")
	if code != ExitFindings || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	var got struct {
		Sources []struct {
			Name, State string
			Count       int
		}
		Findings []struct{ Host, Message string }
	}
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatal(err)
	}
	for _, s := range got.Sources {
		skipped := s.Name == "proc" || s.Name == "systemd"
		if s.Name == "docker" && s.Count != 6 || !skipped && s.State != "ok" {
			t.Errorf("source %+v", s)
		}
	}
	msg := map[string]string{}
	for _, f := range got.Findings {
		msg[f.Host] = f.Message
	}
	want := map[string]string{
		"app.example.org":     "unix:/tmp/backend.socket",
		"sock.example.com":    "unix:/run/app.sock",
		"bastion.example.com": "bastion",
		"h2.example.com":      "localhost:8081",
		"ssh.example.com":     "localhost:22",
		"*.apps.example.com":  "localhost:2368",
		"old.example.com":     "auth detected (basicauth)",
		"gitlab.example.com":  "localhost:8080",
	}
	for host, frag := range want {
		if !strings.Contains(msg[host], frag) {
			t.Errorf("%s: %q lacks %q", host, msg[host], frag)
		}
	}
	for host, m := range msg {
		if strings.Contains(m, "unix:80") {
			t.Errorf("%s still reads a socket as a port: %s", host, m)
		}
	}
}

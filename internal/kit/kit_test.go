// Package kit holds the acceptance tests for the repository's maintenance
// files: Dependabot config, the auto-merge gate, CI shape, the weekly upkeep
// job, hygiene files and the committed dossier. It has no product code.
package kit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const root = "../.."

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func exists(rel string) bool {
	_, err := os.Stat(filepath.Join(root, rel))
	return err == nil
}

func workflows(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(root, ".github/workflows/*.yml"))
	if err != nil || len(m) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	var out []string
	for _, p := range m {
		out = append(out, filepath.Base(p))
	}
	return out
}

func stripComments(s string) string {
	return regexp.MustCompile(`(?m)^\s*#.*$`).ReplaceAllString(s, "")
}

func mustMatch(t *testing.T, pattern, s string) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(s) {
		t.Errorf("expected a match for %q", pattern)
	}
}

func mustNotMatch(t *testing.T, pattern, s, what string) {
	t.Helper()
	if regexp.MustCompile(pattern).MatchString(s) {
		t.Errorf("%s: unexpected match for %q", what, pattern)
	}
}

func TestDependabotWeeklyGroupedWithCooldown(t *testing.T) {
	y := read(t, ".github/dependabot.yml")
	mustMatch(t, `package-ecosystem: gomod`, y)
	mustMatch(t, `package-ecosystem: github-actions`, y)
	mustNotMatch(t, `package-ecosystem: (npm|docker|pip)`, y, "only ecosystems the repo uses")
	if n := strings.Count(y, "interval: weekly"); n != 2 {
		t.Errorf("want both ecosystems weekly, got %d weekly intervals", n)
	}
	mustNotMatch(t, `interval: (daily|monthly)`, y, "schedule")
	if n := len(regexp.MustCompile(`cooldown:\s*\n\s+default-days: 7`).FindAllString(y, -1)); n != 2 {
		t.Errorf("want a 7 day cooldown on both ecosystems, got %d", n)
	}
	mustMatch(t, `(?s)groups:.*update-types:.*- minor.*- patch`, y)
}

func TestAutomergeWorkflowShape(t *testing.T) {
	y := stripComments(read(t, ".github/workflows/dependabot-automerge.yml"))
	mustMatch(t, `(?m)^on:\s*\n\s+pull_request:`, y)
	mustNotMatch(t, `pull_request_target`, y, "automerge must never use pull_request_target")
	mustMatch(t, `github\.event\.pull_request\.user\.login == 'dependabot\[bot\]'`, y)
	mustMatch(t, `github\.event\.pull_request\.head\.repo\.full_name == github\.repository`, y)
	mustMatch(t, `gh pr merge --auto --squash`, y)
	mustMatch(t, `(?m)^permissions: \{\}`, y)
	mustMatch(t, `dependabot/fetch-metadata@[0-9a-f]{40}`, y)
}

func TestNoWorkflowExpandsUntrustedText(t *testing.T) {
	re := `\$\{\{\s*github\.(head_ref|event\.(pull_request\.(title|body|head\.(ref|label))|issue\.(title|body)|comment\.body|review\.body))`
	for _, f := range workflows(t) {
		mustNotMatch(t, re, read(t, ".github/workflows/"+f), f)
	}
}

func TestThirdPartyActionsPinnedBySHA(t *testing.T) {
	uses := regexp.MustCompile(`uses:\s*([^\s#]+)`)
	pinned := regexp.MustCompile(`@[0-9a-f]{40}$`)
	for _, f := range workflows(t) {
		for _, m := range uses.FindAllStringSubmatch(read(t, ".github/workflows/"+f), -1) {
			ref := m[1]
			if strings.HasPrefix(ref, "actions/") || strings.HasPrefix(ref, "./") {
				continue
			}
			if !pinned.MatchString(ref) {
				t.Errorf("%s: %s is not pinned by full SHA", f, ref)
			}
		}
	}
}

func TestEveryWorkflowDeclaresPermissions(t *testing.T) {
	for _, f := range workflows(t) {
		y := read(t, ".github/workflows/"+f)
		mustMatch(t, `(?m)^permissions:`, y)
		mustNotMatch(t, `permissions:\s*write-all`, y, f)
	}
}

// The release workflow keeps its behaviour: goreleaser on a v* tag. The action
// is pinned by SHA. Any major version will do, so a Dependabot bump of the
// action does not fail this test.
func TestReleaseWorkflowUnchanged(t *testing.T) {
	y := read(t, ".github/workflows/release.yml")
	mustMatch(t, `tags: \["v\*"\]`, y)
	mustMatch(t, `goreleaser/goreleaser-action@[0-9a-f]{40} # v[0-9.]+`, y)
	mustMatch(t, `args: release --clean`, y)
}

func gate(t *testing.T, deps any, raw string) int {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed, cannot run the gate script")
	}
	env := []string{}
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "DEPS=") {
			env = append(env, e)
		}
	}
	if raw != "" {
		env = append(env, "DEPS="+raw)
	} else if deps != nil {
		b, _ := json.Marshal(deps)
		env = append(env, "DEPS="+string(b))
	}
	cmd := exec.Command(node, filepath.Join(root, ".github/scripts/automerge-eligible.mjs"))
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("run gate: %v", err)
	}
	return 0
}

func d(eco, name, typ string) map[string]string {
	return map[string]string{"packageEcosystem": eco, "dependencyName": name, "updateType": "version-update:semver-" + typ}
}

func TestGateGoPatchAndMinorMergeMajorsWait(t *testing.T) {
	for _, typ := range []string{"patch", "minor"} {
		if c := gate(t, []any{d("go_modules", "gopkg.in/yaml.v3", typ)}, ""); c != 0 {
			t.Errorf("go %s should be eligible, exit %d", typ, c)
		}
	}
	if c := gate(t, []any{d("go_modules", "gopkg.in/yaml.v3", "major")}, ""); c == 0 {
		t.Error("go major must wait for a human")
	}
}

func TestGateActionsOnlyFromActionsOrgMajorsIncluded(t *testing.T) {
	if c := gate(t, []any{d("github_actions", "actions/checkout", "major")}, ""); c != 0 {
		t.Errorf("actions/ major should be eligible, exit %d", c)
	}
	for _, name := range []string{"someone/else", "actions-evil/checkout", "dependabot/fetch-metadata", "goreleaser/goreleaser-action"} {
		if c := gate(t, []any{d("github_actions", name, "patch")}, ""); c == 0 {
			t.Errorf("%s must not auto-merge", name)
		}
	}
}

func TestGateOneIneligibleBlocksGroup(t *testing.T) {
	mixed := []any{d("go_modules", "a", "patch"), d("go_modules", "b", "major")}
	if c := gate(t, mixed, ""); c == 0 {
		t.Error("a group with a major must not merge")
	}
}

func TestGateBadMetadataNeverMerges(t *testing.T) {
	if gate(t, []any{}, "") == 0 {
		t.Error("empty list merged")
	}
	if gate(t, nil, "not json") == 0 {
		t.Error("malformed metadata merged")
	}
	if gate(t, nil, "") == 0 {
		t.Error("missing metadata merged")
	}
	if gate(t, []any{d("npm_and_yarn", "a", "patch")}, "") == 0 {
		t.Error("an ecosystem this repo does not use merged")
	}
	if gate(t, []any{d("docker", "alpine", "patch")}, "") == 0 {
		t.Error("docker merged")
	}
}

func ciJobName(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^  test:\n    name: (.+)$`).FindStringSubmatch(read(t, ".github/workflows/ci.yml"))
	if m == nil {
		t.Fatal("ci.yml test job has no explicit name")
	}
	return strings.TrimSpace(m[1])
}

func TestCIWeeklyScheduleAndRulesetMatchesCheckNames(t *testing.T) {
	ci := read(t, ".github/workflows/ci.yml")
	mustMatch(t, `(?s)schedule:\s*\n\s+- cron:`, ci)
	mustMatch(t, `workflow_dispatch:`, ci)
	if !strings.Contains(ci, "go vet ./...") || !strings.Contains(ci, "go test -race ./...") {
		t.Error("ci.yml lost its existing vet and test steps")
	}
	var rs struct {
		Target       string `json:"target"`
		Enforcement  string `json:"enforcement"`
		BypassActors []struct {
			ActorID    int    `json:"actor_id"`
			ActorType  string `json:"actor_type"`
			BypassMode string `json:"bypass_mode"`
		} `json:"bypass_actors"`
		Conditions struct {
			RefName struct {
				Include []string `json:"include"`
			} `json:"ref_name"`
		} `json:"conditions"`
		Rules []struct {
			Type       string `json:"type"`
			Parameters struct {
				Checks []struct {
					Context string `json:"context"`
				} `json:"required_status_checks"`
			} `json:"parameters"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(read(t, ".github/rulesets/main.json")), &rs); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs.Rules {
		if r.Type == "required_status_checks" {
			for _, c := range r.Parameters.Checks {
				got = append(got, c.Context)
			}
		}
	}
	sort.Strings(got)
	want := []string{ciJobName(t)}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ruleset requires %v, ci.yml reports %v", got, want)
	}
	if len(rs.BypassActors) != 1 || rs.BypassActors[0].ActorID != 5 || rs.BypassActors[0].ActorType != "RepositoryRole" || rs.BypassActors[0].BypassMode != "always" {
		t.Errorf("bypass actors: %+v", rs.BypassActors)
	}
	if rs.Target != "branch" || rs.Enforcement != "active" {
		t.Errorf("target %q enforcement %q", rs.Target, rs.Enforcement)
	}
	if fmt.Sprint(rs.Conditions.RefName.Include) != "[refs/heads/main]" {
		t.Errorf("ruleset include: %v", rs.Conditions.RefName.Include)
	}
	mustMatch(t, `actions/workflows/ci\.yml/badge\.svg`, read(t, "README.md"))
}

func TestUpkeepWorkflow(t *testing.T) {
	y := read(t, ".github/workflows/upkeep.yml")
	mustMatch(t, `(?s)schedule:\s*\n\s+- cron: "[^"]+ \* \* \d"`, y)
	mustMatch(t, `lycheeverse/lychee-action@[0-9a-f]{40}`, y)
	mustMatch(t, `--max-retries`, y)
	mustMatch(t, `npm install -g github:kd-011/dossier-scribe#v\d+\.\d+\.\d+\b`, y)
	mustNotMatch(t, `dossier-scribe#(main|master)\b`, y, "install must use a tag")
	mustMatch(t, `sync-issue\.sh link-rot`, y)
	mustMatch(t, `sync-issue\.sh dossier-drift`, y)
	mustMatch(t, `fetch-depth: 0`, y)
	if !exists(".github/scripts/sync-issue.sh") {
		t.Error("sync-issue.sh missing")
	}
}

func runSync(t *testing.T, existing bool, existingBody string, withBody bool) []string {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	issues := "[]"
	if existing {
		issues = `[{"number":7,"title":"T"}]`
	}
	stub := fmt.Sprintf("#!/bin/sh\necho \"$*\" >> %q\ncase \"$1 $2\" in\n  \"label create\") exit 0 ;;\n  \"issue list\") echo '%s' ;;\n  \"issue view\") printf '%%s' '%s' ;;\nesac\n", log, issues, existingBody)
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(dir, "body.md")
	if err := os.WriteFile(body, []byte("problem text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script, _ := filepath.Abs(filepath.Join(root, ".github/scripts/sync-issue.sh"))
	args := []string{script, "lbl", "T"}
	if withBody {
		args = append(args, body)
	}
	cmd := exec.Command("sh", args...)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sync-issue.sh: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(log)
	var calls []string
	for _, l := range strings.Split(string(b), "\n") {
		if regexp.MustCompile(`^issue (create|edit|close)`).MatchString(l) {
			f := strings.Fields(l)
			if len(f) > 3 {
				f = f[:3]
			}
			calls = append(calls, strings.Join(f, " "))
		}
	}
	return calls
}

func TestSyncIssueOpensOnceNeverDuplicatesClosesWhenClean(t *testing.T) {
	if got := runSync(t, false, "", true); fmt.Sprint(got) != "[issue create --title]" {
		t.Errorf("new problem: %v", got)
	}
	if got := runSync(t, true, "old", true); fmt.Sprint(got) != "[issue edit 7]" {
		t.Errorf("changed body: %v", got)
	}
	if got := runSync(t, true, "problem text", true); len(got) != 0 {
		t.Errorf("unchanged body should be left alone: %v", got)
	}
	if got := runSync(t, true, "", false); fmt.Sprint(got) != "[issue close 7]" {
		t.Errorf("clean with open issue: %v", got)
	}
	if got := runSync(t, false, "", false); len(got) != 0 {
		t.Errorf("clean with no issue should do nothing: %v", got)
	}
}

func TestHygieneFiles(t *testing.T) {
	for _, f := range []string{"CODE_OF_CONDUCT.md", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md", ".github/PULL_REQUEST_TEMPLATE.md", ".github/ISSUE_TEMPLATE/bug_report.yml", ".github/ISSUE_TEMPLATE/config.yml"} {
		if !exists(f) {
			t.Errorf("missing %s", f)
		}
	}
	sec := read(t, "SECURITY.md")
	mustMatch(t, `(?i)private vulnerability reporting`, sec)
	mustNotMatch(t, `[\w.+-]+@[\w-]+\.[\w.]+`, sec, "no email address in SECURITY.md")
}

func TestKitFilesStayPublicSafe(t *testing.T) {
	files := []string{"SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md", "CONTRIBUTING.md", "README.md",
		".github/dependabot.yml", ".github/PULL_REQUEST_TEMPLATE.md", ".github/ISSUE_TEMPLATE/bug_report.yml",
		".github/ISSUE_TEMPLATE/config.yml", ".github/scripts/automerge-eligible.mjs", ".github/scripts/sync-issue.sh",
		"dossier-scribe.json", "dossiers/unlisted.md", "dossiers/.dossier-lock.json"}
	for _, w := range workflows(t) {
		files = append(files, ".github/workflows/"+w)
	}
	banned := regexp.MustCompile(`(?i)\x{2014}|/home/|gmail|Co-Authored-By`)
	for _, f := range files {
		if m := banned.FindString(read(t, f)); m != "" {
			t.Errorf("%s contains %q", f, m)
		}
	}
}

func TestSocialPreviewIs1280x640PNG(t *testing.T) {
	b := []byte(read(t, ".github/social-preview.png"))
	if len(b) < 24 || string(b[1:4]) != "PNG" {
		t.Fatal("not a PNG")
	}
	w := int(b[16])<<24 | int(b[17])<<16 | int(b[18])<<8 | int(b[19])
	h := int(b[20])<<24 | int(b[21])<<16 | int(b[22])<<8 | int(b[23])
	if w != 1280 || h != 640 {
		t.Errorf("size %dx%d", w, h)
	}
}

func TestDossierHasFiveToFifteenCitedClaims(t *testing.T) {
	doc := read(t, "dossiers/unlisted.md")
	cited := strings.Count(doc, "<!-- src:")
	if cited < 5 || cited > 15 {
		t.Errorf("cited claims: %d", cited)
	}
	var lock struct {
		Docs map[string]struct {
			Claims map[string]json.RawMessage `json:"claims"`
		} `json:"docs"`
	}
	if err := json.Unmarshal([]byte(read(t, "dossiers/.dossier-lock.json")), &lock); err != nil {
		t.Fatal(err)
	}
	if n := len(lock.Docs["unlisted"].Claims); n != cited {
		t.Errorf("lock pins %d claims, dossier cites %d", n, cited)
	}
}

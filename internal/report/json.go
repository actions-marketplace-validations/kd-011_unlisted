package report

import (
	"encoding/json"
	"io"

	"github.com/kd-011/unlisted/internal/check"
	"github.com/kd-011/unlisted/internal/discover"
	"github.com/kd-011/unlisted/internal/probe"
)

// SchemaVersion changes only on a breaking change to the JSON output. New
// optional fields are not breaking. See docs/json.md.
const SchemaVersion = "unlisted/v1"

// JSON is the stable machine-readable report.
type JSON struct {
	Schema   string            `json:"schema"`
	Version  string            `json:"version"`
	Registry string            `json:"registry"`
	Services int               `json:"services"`
	Sources  []discover.Status `json:"sources"`
	Summary  JSONSummary       `json:"summary"`
	Findings []check.Finding   `json:"findings"`
	Probes   *[]probe.Result   `json:"probes,omitempty"`
	Notes    []string          `json:"notes"`
}

// JSONSummary counts findings. Every type and severity is always present, so
// consumers never need a missing-key check.
type JSONSummary struct {
	Total      int            `json:"total"`
	ByType     map[string]int `json:"by_type"`
	BySeverity map[string]int `json:"by_severity"`
	FailOn     []string       `json:"fail_on"`
	Failing    int            `json:"failing"`
	ExitCode   int            `json:"exit_code"`
}

func BuildJSON(r check.Report, version string, failOn map[check.Type]bool, exit int) JSON {
	j := JSON{
		Schema: SchemaVersion, Version: version, Registry: r.Registry, Services: r.Services,
		Sources: r.Sources, Findings: r.Findings, Notes: r.Notes,
	}
	if j.Sources == nil {
		j.Sources = []discover.Status{}
	}
	if j.Findings == nil {
		j.Findings = []check.Finding{}
	}
	if r.NoRegistry {
		j.Notes = append([]string{check.NoRegistryNote}, j.Notes...)
	}
	if j.Notes == nil {
		j.Notes = []string{}
	}
	for i := range j.Findings {
		if j.Findings[i].Where == nil {
			j.Findings[i].Where = []check.Location{}
		}
	}
	if r.ProbeRan {
		ps := r.Probes
		if ps == nil {
			ps = []probe.Result{}
		}
		j.Probes = &ps
	}
	j.Summary = JSONSummary{
		Total: len(r.Findings), ByType: map[string]int{}, BySeverity: map[string]int{"high": 0, "medium": 0, "low": 0},
		FailOn: []string{}, Failing: r.Failing(failOn), ExitCode: exit,
	}
	for _, t := range check.Types {
		j.Summary.ByType[string(t)] = 0
		if failOn[t] {
			j.Summary.FailOn = append(j.Summary.FailOn, string(t))
		}
	}
	for _, f := range r.Findings {
		j.Summary.ByType[string(f.Type)]++
		j.Summary.BySeverity[string(f.Severity)]++
	}
	return j
}

func WriteJSON(w io.Writer, j JSON) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(j)
}

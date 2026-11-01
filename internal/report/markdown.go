package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/kd-011/unlisted/internal/check"
)

// Markdown writes a report that pastes cleanly into an issue or README.
func Markdown(w io.Writer, r check.Report) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("## unlisted report")
	p("")
	p("Registry `%s`, %d %s declared.", r.Registry, r.Services, plural(r.Services, "service", "services"))
	p("")
	if len(r.Findings) == 0 {
		p("Nothing unlisted. Everything exposed is in the registry, and everything in the registry is being served.")
	}
	counts := r.Counts()
	for _, t := range check.Types {
		if counts[t] == 0 {
			continue
		}
		p("### %s (%d)", t.Title(), counts[t])
		p("")
		p("%s.", capitalise(t.Blurb()))
		p("")
		p("| Severity | Service | Found | Where | Fix |")
		p("| --- | --- | --- | --- | --- |")
		for _, f := range r.Findings {
			if f.Type != t {
				continue
			}
			var where []string
			for _, l := range f.Where {
				where = append(where, "`"+whereText(l)+"`")
			}
			p("| %s | %s | %s | %s | %s |", f.Severity, cell(f.Service), cell(f.Message), strings.Join(where, "<br>"), cell(f.Fix))
		}
		p("")
	}
	for _, n := range r.Notes {
		p("> %s", n)
		p("")
	}
	var parts []string
	for _, t := range check.Types {
		if counts[t] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[t], strings.ToLower(t.Title())))
		}
	}
	if len(parts) > 0 {
		p("**%d %s**: %s", len(r.Findings), plural(len(r.Findings), "finding", "findings"), strings.Join(parts, ", "))
	}
}

func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

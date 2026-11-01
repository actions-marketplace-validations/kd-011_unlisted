package report

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/kd-011/unlisted/internal/check"
)

const ruleWidth = 78

// Text writes the terminal report. This is the screenshot, so the layout is
// deliberate: one block per finding type, a card per finding, the fix last.
func Text(w io.Writer, r check.Report, st Style) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	p("")
	p("  %s  %s", st.BoldColor(255, "unlisted"),
		st.Grey(fmt.Sprintf("%s · %d %s declared", r.Registry, r.Services, plural(r.Services, "service", "services"))))
	p("")
	sourcesLine(w, r, st)
	p("")

	counts := r.Counts()
	if len(r.Findings) == 0 {
		p("  %s %s", st.BoldColor(114, "✓"), st.Bold("Nothing unlisted."))
		p("    %s", st.Grey("Everything exposed is in the registry, and everything in the registry is being served."))
		p("")
		if r.ProbeRan {
			probeBlock(w, r, st)
		}
		notes(w, r, st)
		p("")
		return
	}

	for _, t := range check.Types {
		if counts[t] == 0 {
			continue
		}
		heading(w, t, counts[t], st)
		compactStarted := false
		for _, f := range r.Findings {
			if f.Type != t {
				continue
			}
			if f.Compact {
				if !compactStarted {
					if counts[t] > countCompact(r, t) {
						p("  %s", st.Grey("listening ports"))
					}
					compactStarted = true
				}
				compactRow(w, f, st)
				continue
			}
			card(w, f, st)
		}
		if compactStarted {
			p("")
		}
	}

	if r.ProbeRan {
		probeBlock(w, r, st)
	}
	notes(w, r, st)
	summary(w, r, st)
	p("")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func countCompact(r check.Report, t check.Type) int {
	n := 0
	for _, f := range r.Findings {
		if f.Type == t && f.Compact {
			n++
		}
	}
	return n
}

func sevColor(st Style, s check.Severity, text string) string {
	switch s {
	case check.High:
		return st.BoldColor(203, text)
	case check.Medium:
		return st.BoldColor(179, text)
	}
	return st.BoldColor(110, text)
}

func typeColor(t check.Type) int {
	switch t {
	case check.Unregistered:
		return 203
	case check.Dead:
		return 215
	case check.NoAuth:
		return 179
	case check.Drift:
		return 110
	}
	return 141
}

func heading(w io.Writer, t check.Type, n int, st Style) {
	title := st.BoldColor(typeColor(t), t.Title())
	count := st.Bold(strconv.Itoa(n))
	fmt.Fprintf(w, "  %s  %s  %s\n", title, count, st.Grey(t.Blurb()))
	fmt.Fprintf(w, "  %s\n", st.Grey(strings.Repeat("─", ruleWidth)))
}

func card(w io.Writer, f check.Finding, st Style) {
	bar := sevColor(st, f.Severity, "▌")
	tag := sevColor(st, f.Severity, pad(strings.ToUpper(string(f.Severity)), 8))
	name := st.Bold(f.Service)
	if f.Host != "" && f.Host != f.Service {
		name += "  " + st.Grey(f.Host)
	}
	var where []string
	for _, loc := range f.Where {
		where = append(where, whereText(loc))
	}
	fmt.Fprintf(w, "  %s %s %s\n", bar, tag, name)
	fmt.Fprintf(w, "  %s          %s\n", bar, f.Message)
	fmt.Fprintf(w, "  %s          %s\n", bar, st.Grey(strings.Join(where, "  ·  ")))
	fmt.Fprintf(w, "  %s          %s %s\n", bar, st.Green("fix"), st.Dim(f.Fix))
	fmt.Fprintln(w)
}

func whereText(l check.Location) string {
	switch {
	case l.File != "" && l.Line > 0:
		return fmt.Sprintf("%s:%d", l.File, l.Line)
	case l.File != "":
		return l.File
	case l.Detail != "":
		return l.Source + ": " + l.Detail
	}
	return l.Source
}

func compactRow(w io.Writer, f check.Finding, st Style) {
	dot := sevColor(st, f.Severity, "●")
	port := st.Bold(pad(":"+strconv.Itoa(f.Port), 7))
	who := pad(truncate(f.Service, 24), 25)
	fmt.Fprintf(w, "  %s %s%s%s\n", dot, port, who, st.Grey(f.Short))
}

func sourcesLine(w io.Writer, r check.Report, st Style) {
	var parts []string
	for _, s := range r.Sources {
		var mark, detail string
		switch s.State {
		case "ok":
			mark = st.Green("●")
			detail = fmt.Sprintf("%d %s", s.Count, trimUnit(s.Unit))
		case "error":
			mark = st.Amber("●")
			detail = "unreadable"
		default:
			mark = st.Grey("○")
			detail = s.State
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", mark, s.Name, st.Grey(detail)))
	}
	// Two lines keeps it inside 80 columns with six sources.
	half := (len(parts) + 1) / 2
	fmt.Fprintf(w, "  %s\n", strings.Join(parts[:half], "   "))
	if half < len(parts) {
		fmt.Fprintf(w, "  %s\n", strings.Join(parts[half:], "   "))
	}
	for _, s := range r.Sources {
		if s.State == "error" {
			fmt.Fprintf(w, "  %s\n", st.Amber(s.Name+": "+s.Detail))
		}
	}
}

// trimUnit drops the "owners hidden" tail so the sources line stays compact.
func trimUnit(u string) string {
	if i := strings.Index(u, ","); i >= 0 {
		return u[:i]
	}
	return u
}

func probeBlock(w io.Writer, r check.Report, st Style) {
	fmt.Fprintf(w, "  %s  %s\n", st.BoldColor(255, "PROBE"), st.Grey("what each registry host answered"))
	fmt.Fprintf(w, "  %s\n", st.Grey(strings.Repeat("─", ruleWidth)))
	for _, p := range r.Probes {
		status := ""
		switch {
		case p.Err != "":
			status = st.Red(p.Err)
		case p.Status >= 500:
			status = st.Red(strconv.Itoa(p.Status))
		default:
			status = st.Green(strconv.Itoa(p.Status))
		}
		cert := ""
		if p.CertDays != nil {
			cert = fmt.Sprintf("cert %dd", *p.CertDays)
		}
		hint := ""
		if p.AuthHint != "" {
			hint = "auth: " + p.AuthHint
		}
		fmt.Fprintf(w, "  %s%s%s %s\n", pad(p.Host, 34), pad(status, 6+ansiLen(status)), pad(cert, 11), st.Grey(hint))
	}
	fmt.Fprintln(w)
}

// ansiLen is how many invisible bytes the colouring added, so padding by rune
// count still lines up.
func ansiLen(s string) int { return width(s) - visible(s) }

func visible(s string) int {
	n, in := 0, false
	for _, r := range s {
		switch {
		case r == 0x1b:
			in = true
		case in && r == 'm':
			in = false
		case !in:
			n++
		}
	}
	return n
}

func notes(w io.Writer, r check.Report, st Style) {
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  %s %s\n", st.Grey("note"), st.Grey(n))
	}
	if len(r.Notes) > 0 {
		fmt.Fprintln(w)
	}
}

func summary(w io.Writer, r check.Report, st Style) {
	counts := r.Counts()
	var parts []string
	for _, t := range check.Types {
		if counts[t] > 0 {
			parts = append(parts, fmt.Sprintf("%s %s", st.BoldColor(typeColor(t), strconv.Itoa(counts[t])), strings.ToLower(t.Title())))
		}
	}
	n := len(r.Findings)
	fmt.Fprintf(w, "  %s %s  %s\n", st.BoldColor(203, "✗"),
		st.Bold(fmt.Sprintf("%d %s", n, plural(n, "finding", "findings"))), strings.Join(parts, st.Grey(" · ")))
}

// IsTTY reports whether f is a terminal, without a dependency: a character
// device is good enough to decide about colour.
func IsTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

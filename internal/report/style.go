// Package report renders a check.Report as terminal text, JSON or Markdown.
package report

import (
	"os"
	"strings"
)

// Style decides whether escape codes are emitted.
type Style struct{ Color bool }

// DetectColor applies the usual rules: --no-color and NO_COLOR win, then
// CLICOLOR_FORCE, then whether the output is a terminal.
func DetectColor(noColorFlag, isTTY bool) bool {
	if noColorFlag {
		return false
	}
	// no-color.org: the variable counts only when it is non-empty.
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return isTTY
}

const (
	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
)

// 256-colour values chosen to read on both dark and light terminals.
func fg(n int) string { return "\x1b[38;5;" + itoa(n) + "m" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (s Style) wrap(code, text string) string {
	if !s.Color || text == "" {
		return text
	}
	return code + text + reset
}

func (s Style) Bold(t string) string  { return s.wrap(bold, t) }
func (s Style) Dim(t string) string   { return s.wrap(dim, t) }
func (s Style) Red(t string) string   { return s.wrap(fg(203), t) }
func (s Style) Amber(t string) string { return s.wrap(fg(179), t) }
func (s Style) Blue(t string) string  { return s.wrap(fg(110), t) }
func (s Style) Green(t string) string { return s.wrap(fg(114), t) }
func (s Style) Grey(t string) string  { return s.wrap(fg(244), t) }

// BoldColor applies bold plus a colour in one sequence.
func (s Style) BoldColor(code int, t string) string {
	return s.wrap(bold+fg(code), t)
}

// width counts runes, which is all the layout needs: every glyph used is one
// column wide.
func width(s string) int { return len([]rune(s)) }

func pad(s string, n int) string {
	if w := width(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

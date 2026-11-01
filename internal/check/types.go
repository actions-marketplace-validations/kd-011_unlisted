// Package check reconciles what the registry declares against what discovery
// found, and turns the differences into findings.
package check

import "strings"

// Type is a kind of finding.
type Type string

const (
	Unregistered Type = "unregistered"
	Dead         Type = "dead"
	NoAuth       Type = "noauth"
	Drift        Type = "drift"
	Cert         Type = "cert"
)

// Types in report order.
var Types = []Type{Unregistered, Dead, NoAuth, Drift, Cert}

// Title is the upper-case heading for a type.
func (t Type) Title() string { return strings.ToUpper(string(t)) }

// Blurb is the one-line gloss shown beside the heading.
func (t Type) Blurb() string {
	switch t {
	case Unregistered:
		return "exposed, but not in your registry"
	case Dead:
		return "in your registry, but nothing serves it"
	case NoAuth:
		return "reachable with no auth detected in front"
	case Drift:
		return "registry and reality disagree on the port"
	case Cert:
		return "TLS certificate problems"
	}
	return ""
}

// Severity ranks a finding.
type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
)

func (s Severity) rank() int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	}
	return 1
}

// Location is where a fact was read from.
type Location struct {
	Source string `json:"source"`
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Finding is one gap between the registry and the machine.
type Finding struct {
	Type     Type       `json:"type"`
	Severity Severity   `json:"severity"`
	Service  string     `json:"service"`
	Host     string     `json:"host,omitempty"`
	Port     int        `json:"port,omitempty"`
	Message  string     `json:"message"`
	Where    []Location `json:"where"`
	Fix      string     `json:"fix"`
	// Compact marks low-value rows (a bare listening port) that the text report
	// prints on one line instead of a card. It is presentation, not schema.
	Compact bool   `json:"-"`
	Short   string `json:"-"` // the one-line form shown for Compact rows
}

// ParseTypes reads a --fail-on list. "all" and "none" are accepted.
func ParseTypes(s string) (map[Type]bool, error) {
	out := map[Type]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		switch p {
		case "":
		case "none":
		case "all":
			for _, t := range Types {
				out[t] = true
			}
		default:
			ok := false
			for _, t := range Types {
				if string(t) == p {
					out[t], ok = true, true
				}
			}
			if !ok {
				return nil, &badType{p}
			}
		}
	}
	return out, nil
}

type badType struct{ v string }

func (b *badType) Error() string {
	return "unknown finding type " + b.v + " (use unregistered, dead, noauth, drift, cert, all or none)"
}

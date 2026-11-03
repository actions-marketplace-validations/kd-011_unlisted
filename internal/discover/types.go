// Package discover finds what a machine actually exposes. Each source is a
// small reader over one config file or kernel interface, and each one degrades
// to "absent" or "error" instead of failing the run: a box with no Caddy must
// still get a useful report.
package discover

import (
	"errors"
	"sort"
)

// ErrAbsent means the source's files or tools are not on this machine. It is
// not a failure, only a fact worth showing.
var ErrAbsent = errors.New("not found")

// Exposure is a public hostname some proxy or tunnel is willing to serve.
type Exposure struct {
	Source string // cloudflared | caddy | nginx
	Host   string // lowercase hostname, may start with "*."
	Origin Origin // where the hostname is sent; zero for static sites
	Auth   bool   // an auth directive was seen in front of this host
	AuthBy string // the directive, e.g. forward_auth
	File   string // virtual path of the config file
	Line   int
}

// Listener is a TCP port something is listening on.
type Listener struct {
	Port    int
	Addr    string // bind address as text
	Public  bool   // bound to something other than loopback
	PID     int
	Process string // friendly process name
	Unit    string // systemd unit, if known
	// Container fields come from the Docker API.
	Container     string
	Image         string
	ContainerPort int
	Sources       []string // proc | docker
}

// Name is the best label for a listener.
func (l Listener) Name() string {
	switch {
	case l.Container != "":
		return l.Container
	case l.Unit != "":
		return l.Unit
	case l.Process != "":
		return l.Process
	}
	return ""
}

type Result struct {
	Exposures []Exposure
	Listeners []Listener
	Units     map[string]string // systemd unit -> description
	Count     int               // headline number for the sources line
	Unit      string            // what Count counts, e.g. "rules"
	Paths     []string
}

type Source interface {
	Name() string
	Discover(env Env) (Result, error)
}

type Status struct {
	Name   string   `json:"name"`
	State  string   `json:"state"` // ok | absent | skipped | error
	Count  int      `json:"count"`
	Unit   string   `json:"unit,omitempty"`
	Detail string   `json:"detail,omitempty"`
	Paths  []string `json:"paths,omitempty"`
}

// Snapshot is everything discovered, merged.
type Snapshot struct {
	Exposures []Exposure
	Listeners []Listener
	Units     map[string]string
	Sources   []Status
}

// Loaded reports whether the named source ran and found its files.
func (s Snapshot) Loaded(name string) bool {
	for _, st := range s.Sources {
		if st.Name == name {
			return st.State == "ok"
		}
	}
	return false
}

// AllSources is the default set, in report order.
func AllSources() []Source {
	return []Source{Cloudflared{}, Caddy{}, Nginx{}, Docker{}, Proc{}, Systemd{}}
}

// Run executes every source. A source error becomes a Status, never a return
// value, so one broken source cannot stop the report.
func Run(env Env, sources []Source) Snapshot {
	var snap Snapshot
	snap.Units = map[string]string{}
	listeners := map[lkey]*Listener{}

	for _, src := range sources {
		st := Status{Name: src.Name()}
		if env.Skip[src.Name()] {
			st.State = "skipped"
			st.Detail = "--skip"
			snap.Sources = append(snap.Sources, st)
			continue
		}
		res, err := src.Discover(env)
		st.Paths = res.Paths
		switch {
		case errors.Is(err, ErrAbsent):
			st.State = "absent"
		case err != nil:
			st.State = "error"
			st.Detail = err.Error()
		default:
			st.State = "ok"
			st.Count = res.Count
			st.Unit = res.Unit
		}
		snap.Sources = append(snap.Sources, st)
		if err != nil {
			continue
		}
		snap.Exposures = append(snap.Exposures, res.Exposures...)
		for u, d := range res.Units {
			snap.Units[u] = d
		}
		for _, l := range res.Listeners {
			mergeListener(listeners, l)
		}
	}

	for _, l := range listeners {
		snap.Listeners = append(snap.Listeners, *l)
	}
	sort.Slice(snap.Listeners, func(i, j int) bool {
		a, b := snap.Listeners[i], snap.Listeners[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return !a.Public && b.Public
	})
	attributeUnits(env, &snap)
	return snap
}

// A port bound on 0.0.0.0 and on :: is one thing to a human, and so is the
// docker-proxy socket and the Docker API's view of the same publish. Merging
// on (port, reachability) keeps the report to one line per exposure.
type lkey struct {
	port   int
	public bool
}

func mergeListener(m map[lkey]*Listener, l Listener) {
	k := lkey{l.Port, l.Public}
	cur, ok := m[k]
	if !ok {
		c := l
		m[k] = &c
		return
	}
	if cur.PID == 0 && l.PID != 0 {
		cur.PID, cur.Process = l.PID, l.Process
	}
	if cur.Container == "" && l.Container != "" {
		cur.Container, cur.Image, cur.ContainerPort = l.Container, l.Image, l.ContainerPort
	}
	// Prefer the IPv4 spelling of a wildcard bind: it is what people recognise.
	if cur.Addr == "::" && l.Addr == "0.0.0.0" {
		cur.Addr = l.Addr
	}
	for _, s := range l.Sources {
		has := false
		for _, e := range cur.Sources {
			has = has || e == s
		}
		if !has {
			cur.Sources = append(cur.Sources, s)
		}
	}
}

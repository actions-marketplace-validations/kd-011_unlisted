// Package registry loads the one YAML file a self-hoster maintains: what they
// say they run. Everything else in unlisted is measured; this is the claim the
// measurements are held against.
package registry

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Auth is what the owner says sits in front of a service.
type Auth string

const (
	AuthUnset  Auth = ""
	AuthNone   Auth = "none"              // deliberately open; silences NOAUTH
	AuthProxy  Auth = "proxy"             // reverse proxy or SSO gate in front
	AuthApp    Auth = "app"               // the application logs people in itself
	AuthAccess Auth = "cloudflare-access" // Cloudflare Access policy at the edge
)

var validAuth = map[Auth]bool{AuthNone: true, AuthProxy: true, AuthApp: true, AuthAccess: true}

// Service is one declared service. Every field except Name is optional, but a
// service needs at least one of Host, Port or URL or there is nothing to check.
type Service struct {
	Name   string `yaml:"name"`
	Host   string `yaml:"host"`
	Port   int    `yaml:"port"`
	URL    string `yaml:"url"`
	Auth   Auth   `yaml:"auth"`
	Owner  string `yaml:"owner"`
	Note   string `yaml:"note"`
	Ignore bool   `yaml:"ignore"`

	// Line is where the entry starts in the file, for "where" in findings.
	Line int `yaml:"-"`
}

// Registry is a parsed registry file.
type Registry struct {
	Path     string
	Services []Service
}

var knownFields = []string{"name", "host", "port", "url", "auth", "owner", "note", "ignore"}

// Load reads and validates a registry file.
func Load(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, path)
}

// Parse validates registry YAML. It collects every problem it can find rather
// than stopping at the first, because fixing a registry one error per run is
// miserable.
func Parse(data []byte, path string) (*Registry, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	reg := &Registry{Path: path}
	if doc.Kind == 0 { // empty file
		return reg, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s:%d: top level must be a mapping with a services: list", path, root.Line)
	}
	var list *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i]
		if k.Value != "services" {
			return nil, fmt.Errorf("%s:%d: unknown top-level key %q (expected services)", path, k.Line, k.Value)
		}
		list = root.Content[i+1]
	}
	if list == nil || (list.Kind == yaml.ScalarNode && list.Tag == "!!null") {
		return reg, nil
	}
	if list.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s:%d: services must be a list", path, list.Line)
	}

	var errs []error
	fail := func(line int, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s:%d: %s", path, line, fmt.Sprintf(format, a...)))
	}
	seenHost := map[string]int{}
	for _, item := range list.Content {
		if item.Kind != yaml.MappingNode {
			fail(item.Line, "each service must be a mapping")
			continue
		}
		strict := true
		for i := 0; i+1 < len(item.Content); i += 2 {
			k := item.Content[i]
			if !contains(knownFields, k.Value) {
				strict = false
				if guess := closest(k.Value, knownFields); guess != "" {
					fail(k.Line, "unknown field %q (did you mean %q?)", k.Value, guess)
				} else {
					fail(k.Line, "unknown field %q (allowed: %s)", k.Value, strings.Join(knownFields, ", "))
				}
			}
		}
		if !strict {
			continue
		}
		var s Service
		if err := item.Decode(&s); err != nil {
			fail(item.Line, "%s", strings.TrimPrefix(err.Error(), "yaml: "))
			continue
		}
		s.Line = item.Line
		s.Host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.Host), "."))
		s.Name = strings.TrimSpace(s.Name)
		s.URL = strings.TrimSpace(s.URL)

		if s.Name == "" {
			fail(s.Line, "service has no name")
		}
		if strings.Contains(s.Host, "://") || strings.ContainsAny(s.Host, "/ ") {
			fail(s.Line, "host %q must be a bare hostname, no scheme or path (use url: for that)", s.Host)
		}
		if s.Port < 0 || s.Port > 65535 {
			fail(s.Line, "port %d is out of range", s.Port)
		}
		if s.URL != "" {
			if u, err := url.Parse(s.URL); err != nil || u.Host == "" {
				fail(s.Line, "url %q is not an absolute URL (try http://localhost:8080)", s.URL)
			}
		}
		if s.Auth != AuthUnset && !validAuth[s.Auth] {
			fail(s.Line, "auth %q is not one of none, proxy, app, cloudflare-access", s.Auth)
		}
		if s.Host == "" && s.Port == 0 && s.URL == "" {
			fail(s.Line, "service %q needs at least one of host, port or url", s.Name)
		}
		if s.Host != "" {
			if first, dup := seenHost[s.Host]; dup {
				fail(s.Line, "host %s is already declared on line %d", s.Host, first)
			}
			seenHost[s.Host] = s.Line
		}
		reg.Services = append(reg.Services, s)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return reg, nil
}

// EffectivePort is the port the owner expects the service on: the explicit
// port, else whatever the url says.
func (s Service) EffectivePort() int {
	if s.Port != 0 {
		return s.Port
	}
	if s.URL == "" {
		return 0
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		return 0
	}
	if p := u.Port(); p != "" {
		n, _ := strconv.Atoi(p)
		return n
	}
	switch u.Scheme {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

// URLHost is the host part of url, or "".
func (s Service) URLHost() string {
	if s.URL == "" {
		return ""
	}
	u, err := url.Parse(s.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Label is the best short name for output.
func (s Service) Label() string {
	if s.Name != "" {
		return s.Name
	}
	if s.Host != "" {
		return s.Host
	}
	return "port " + strconv.Itoa(s.EffectivePort())
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// closest suggests a known field for a typo, using edit distance. Only close
// matches are offered so the hint is never noise.
func closest(w string, options []string) string {
	type cand struct {
		s string
		d int
	}
	var cs []cand
	for _, o := range options {
		cs = append(cs, cand{o, lev(w, o)})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].d < cs[j].d })
	if len(cs) > 0 && cs[0].d <= 2 {
		return cs[0].s
	}
	return ""
}

func lev(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

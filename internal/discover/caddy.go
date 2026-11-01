package discover

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Caddy reads a Caddyfile for site addresses, reverse_proxy targets and auth
// directives. The parser is tolerant on purpose: it understands enough of the
// format to be useful and never tries to be Caddy.
type Caddy struct{}

func (Caddy) Name() string { return "caddy" }

func (Caddy) Discover(env Env) (Result, error) {
	shown, real := env.resolve(env.Caddyfile, "/etc/caddy/Caddyfile")
	b, err := os.ReadFile(real)
	if err != nil {
		if os.IsNotExist(err) {
			return Result{}, ErrAbsent
		}
		return Result{}, fmt.Errorf("%s: %w", shown, err)
	}
	res := ParseCaddyfile(b, shown)
	res.Paths = []string{shown}
	return res, nil
}

// Directives that put a login or credential check in front of a site.
var caddyAuth = map[string]bool{
	"forward_auth": true, "basicauth": true, "basic_auth": true,
	"authenticate": true, "authorize": true, "jwtauth": true,
}

var caddyEnv = regexp.MustCompile(`\{\$([A-Za-z0-9_]+)(?::([^}]*))?\}`)

type caddyBlock struct {
	addrs   []string
	line    int
	origin  Origin
	auth    string
	imports []string
	snippet string // set when this block is a (snippet)
}

// ParseCaddyfile extracts one Exposure per site address.
func ParseCaddyfile(data []byte, file string) Result {
	res := Result{Unit: "sites"}
	var blocks []*caddyBlock
	var stack []*caddyBlock // nil entries are nested non-site blocks
	var site *caddyBlock
	// A Caddyfile may hold a single site with no braces at all: the address
	// line, then its directives. That form is decided once, from the first line
	// of the file, so snippets, global options and braced sites can never be
	// mistaken for it. Once it starts, every later line is part of the one site.
	canBeBraceless := caddyBracelessFile(data)
	braceless := false

	for n, raw := range strings.Split(string(data), "\n") {
		line := n + 1
		toks := caddyTokens(raw)
		if len(toks) == 0 {
			continue
		}
		opens := toks[len(toks)-1] == "{"
		if opens {
			toks = toks[:len(toks)-1]
		}
		closes := len(toks) > 0 && toks[0] == "}"
		if closes {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 && !braceless {
				site = nil
			}
			toks = toks[1:]
			if len(toks) == 0 && !opens {
				continue
			}
		}

		switch {
		case braceless && len(stack) == 0:
			if len(toks) > 0 {
				caddyDirective(site, toks, 1)
			}
			if opens {
				stack = append(stack, nil)
			}
		case len(stack) == 0 && opens && len(toks) == 0:
			// Global options block: { ... }
			stack = append(stack, nil)
		case len(stack) == 0 && !opens && !(canBeBraceless && len(blocks) == 0 && caddyAddressLike(toks)):
			// A top-level line with no brace that is not the braceless site:
			// an import or a stray directive. It is never a site address.
		case len(stack) == 0 && (opens || len(toks) > 0):
			// A site address line, with or without a brace.
			b := &caddyBlock{line: line}
			if len(toks) == 1 && strings.HasPrefix(toks[0], "(") && strings.HasSuffix(toks[0], ")") {
				b.snippet = strings.Trim(toks[0], "()")
			} else {
				b.addrs = toks
			}
			blocks = append(blocks, b)
			if opens {
				stack = append(stack, b)
				site = b
			} else if len(blocks) == 1 && b.snippet == "" {
				braceless, site = true, b
			}
		case len(stack) > 0:
			if site != nil && len(toks) > 0 {
				d := len(stack)
				if braceless {
					d++
				}
				caddyDirective(site, toks, d)
			}
			if opens {
				stack = append(stack, nil)
			}
		}
	}

	// Snippets can carry auth, so resolve imports after the whole file is read.
	snippetAuth := map[string]string{}
	for _, b := range blocks {
		if b.snippet != "" && b.auth != "" {
			snippetAuth[b.snippet] = b.auth
		}
	}
	for _, b := range blocks {
		if b.snippet != "" {
			continue
		}
		for _, imp := range b.imports {
			if a, ok := snippetAuth[imp]; ok && b.auth == "" {
				b.auth = a
			}
		}
		for _, addr := range b.addrs {
			host, ok := caddyHost(addr)
			if !ok {
				continue
			}
			res.Exposures = append(res.Exposures, Exposure{
				Source: "caddy", Host: host, Origin: b.origin,
				Auth: b.auth != "", AuthBy: b.auth, File: file, Line: b.line,
			})
			res.Count++
		}
	}
	return res
}

// caddyBracelessFile reports whether the file is the single-site form. Two
// things must hold: the first significant line is a real address with no
// opening brace, and the rest of the file contains no braced site block. The
// second check walks the whole file, skipping the global options block and
// (snippet) definitions, and counts any top-level line that opens a brace and
// starts with something host-shaped. Braces inside directives (basic_auth {,
// handle /x {) sit below the first address and are not top-level sites.
func caddyBracelessFile(data []byte) bool {
	first := true
	depth := 0
	for _, raw := range strings.Split(string(data), "\n") {
		toks := caddyTokens(raw)
		if len(toks) == 0 {
			continue
		}
		if first {
			first = false
			if toks[len(toks)-1] == "{" || !caddyAddressLike(toks) {
				return false
			}
			continue
		}
		if toks[0] == "}" {
			if depth > 0 {
				depth--
			}
			toks = toks[1:]
			if len(toks) == 0 {
				continue
			}
		}
		opens := toks[len(toks)-1] == "{"
		if opens && depth == 0 {
			head := toks[0]
			skip := head == "{" || strings.HasPrefix(head, "(") // global options, snippet
			if !skip && caddyHostShaped(head) {
				return false // a braced site block: this is not the single-site form
			}
		}
		if opens {
			depth++
		}
	}
	return !first
}

// caddyHostShaped reports whether a token looks like a site address rather
// than a directive name.
func caddyHostShaped(tok string) bool {
	if caddyDirectives[tok] {
		return false
	}
	return strings.ContainsAny(tok, ".:*") || strings.HasPrefix(tok, "{$")
}

// Every standard Caddy 2 directive, plus the common auth plugins, so no
// directive name is ever taken for a site address. Keep in step with
// https://caddyserver.com/docs/caddyfile/directives.
var caddyDirectives = func() map[string]bool {
	m := map[string]bool{}
	for _, d := range []string{
		"abort", "acme_server", "basic_auth", "basicauth", "bind", "copy_response",
		"copy_response_headers", "encode", "error", "file_server", "forward_auth", "fs",
		"handle", "handle_errors", "handle_path", "header", "import", "intercept", "invoke",
		"log", "log_append", "log_name", "log_skip", "map", "method", "metrics", "php_fastcgi",
		"push", "redir", "request_body", "request_header", "respond", "reverse_proxy",
		"rewrite", "root", "route", "skip_log", "templates", "tls", "tracing", "try_files",
		"uri", "vars",
		// caddy-security and similar plugins
		"authenticate", "authorize", "jwtauth",
	} {
		m[d] = true
	}
	return m
}()

// caddyAddressLike reports whether a top-level line can be a site address.
func caddyAddressLike(toks []string) bool {
	if len(toks) == 0 || caddyDirectives[toks[0]] || strings.HasPrefix(toks[0], "(") || toks[0] == "{" || toks[0] == "}" {
		return false
	}
	return true
}

// caddyDirective records what one directive tells us about a site. depth is 1
// for a directive directly in the site block. Auth only counts there and only
// when it has no path or named matcher: `basic_auth /admin/*` or anything inside
// `handle /x/*` leaves the rest of the site open, and claiming otherwise would
// hide a NOAUTH finding. This matches how the nginx parser treats sub-locations.
func caddyDirective(b *caddyBlock, toks []string, depth int) {
	name := toks[0]
	switch {
	case name == "reverse_proxy" && b.origin.IsZero():
		args := toks[1:]
		// The first argument may be a matcher (/path/* or @name), not an upstream.
		if caddyMatcher(args) || (len(args) > 0 && args[0] == "*") {
			args = args[1:]
		}
		if len(args) > 0 {
			b.origin = ParseOrigin(args[0])
		}
	case caddyAuth[name]:
		if b.auth == "" && depth == 1 && !caddyMatcher(toks[1:]) {
			b.auth = name
		}
	case name == "import" && len(toks) > 1:
		b.imports = append(b.imports, toks[1])
	}
}

// caddyMatcher reports whether the first argument scopes a directive to a
// path or named matcher. A bare `*` matches everything and is not scoping.
func caddyMatcher(args []string) bool {
	return len(args) > 0 && (strings.HasPrefix(args[0], "/") || strings.HasPrefix(args[0], "@"))
}

// caddyHost normalises a site address to a bare hostname. Port-only addresses,
// localhost and unresolved placeholders are not public hostnames.
func caddyHost(addr string) (string, bool) {
	addr = caddyEnv.ReplaceAllStringFunc(addr, func(m string) string {
		sub := caddyEnv.FindStringSubmatch(m)
		if sub[2] != "" {
			return sub[2]
		}
		return m // leave it; rejected below
	})
	if strings.Contains(addr, "{") {
		return "", false
	}
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}
	if i := strings.Index(addr, "/"); i >= 0 {
		addr = addr[:i]
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = addr[:i]
	}
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" || addr == "localhost" || strings.HasSuffix(addr, ".localhost") {
		return "", false
	}
	return addr, true
}

// caddyTokens splits a line on whitespace, honouring quotes and dropping
// comments. Commas attach to the preceding token in "a.com, b.com {" so they
// are stripped here.
func caddyTokens(line string) []string {
	var toks []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, strings.TrimRight(cur.String(), ","))
			cur.Reset()
		}
	}
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '`':
			quote = r
		case r == '#' && cur.Len() == 0:
			flush()
			return clean(toks)
		case r == ' ' || r == '\t' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return clean(toks)
}

func clean(toks []string) []string {
	out := toks[:0]
	for _, t := range toks {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

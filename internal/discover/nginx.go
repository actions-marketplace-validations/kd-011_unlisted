package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Nginx reads server_name, proxy_pass and auth directives from the config
// files under /etc/nginx. It is a tolerant tokenizer, not an nginx parser:
// includes are followed only by the conventional directories.
type Nginx struct{}

func (Nginx) Name() string { return "nginx" }

func (Nginx) Discover(env Env) (Result, error) {
	shown, real := env.resolve(env.NginxDir, "/etc/nginx")
	if _, err := os.Stat(real); err != nil {
		if os.IsNotExist(err) {
			return Result{}, ErrAbsent
		}
		return Result{}, fmt.Errorf("%s: %w", shown, err)
	}
	var files []string
	for _, pat := range []string{"nginx.conf", "conf.d/*", "sites-enabled/*", "*.conf"} {
		m, _ := filepath.Glob(filepath.Join(real, pat))
		files = append(files, m...)
	}
	sort.Strings(files)
	seen := map[string]bool{}
	var res Result
	res.Unit = "sites"
	res.Paths = []string{shown}
	var all []nginxServer
	// Upstream names resolve across files, so collect first and join after.
	upstreams := map[string]string{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		st, err := os.Stat(f)
		if err != nil || st.IsDir() {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			continue // an unreadable include is not worth failing the source
		}
		rel, _ := filepath.Rel(real, f)
		display := filepath.Join(shown, rel)
		servers, ups := parseNginx(b, display)
		all = append(all, servers...)
		for k, v := range ups {
			upstreams[k] = v
		}
	}
	res.Exposures = nginxExposures(all, upstreams)
	res.Count = len(res.Exposures)
	return res, nil
}

// ParseNginx is the single-buffer entry point used by tests.
func ParseNginx(data []byte, file string) []Exposure {
	servers, ups := parseNginx(data, file)
	return nginxExposures(servers, ups)
}

type nginxServer struct {
	names  []string
	file   string
	line   int
	proxy  string // raw proxy_pass target
	auth   string
	locAny string // proxy_pass from a non-root location, used if no root one
}

type ntok struct {
	s    string
	line int
}

func nginxTokens(data []byte) []ntok {
	var out []ntok
	var cur strings.Builder
	line, start := 1, 1
	var quote byte
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, ntok{cur.String(), start})
			cur.Reset()
		}
	}
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			if cur.Len() == 0 {
				start = line
			}
			quote = c
		case c == '#':
			flush()
			for i < len(data) && data[i] != '\n' {
				i++
			}
			line++
		case c == '\n':
			flush()
			line++
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		case c == ';' || c == '{' || c == '}':
			flush()
			out = append(out, ntok{string(c), line})
		default:
			if cur.Len() == 0 {
				start = line
			}
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func parseNginx(data []byte, file string) ([]nginxServer, map[string]string) {
	toks := nginxTokens(data)
	var servers []nginxServer
	upstreams := map[string]string{}

	type ctx struct{ kind, arg string }
	var stack []ctx
	var cur *nginxServer
	var curUpstream string
	var stmt []ntok

	inServer := func() bool { return cur != nil }
	locRoot := func() bool {
		for _, c := range stack {
			if c.kind == "location" {
				return c.arg == "/"
			}
		}
		return true // server level counts as root
	}

	for _, t := range toks {
		switch t.s {
		case "{":
			kind, arg := "", ""
			if len(stmt) > 0 {
				kind = stmt[0].s
			}
			if len(stmt) > 1 {
				arg = stmt[len(stmt)-1].s
			}
			if kind == "upstream" && len(stmt) > 1 {
				curUpstream = stmt[1].s
			}
			stack = append(stack, ctx{kind, arg})
			if kind == "server" {
				servers = append(servers, nginxServer{file: file, line: t.line})
				cur = &servers[len(servers)-1]
			}
			stmt = nil
		case "}":
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if top.kind == "server" {
					cur = nil
				}
				if top.kind == "upstream" {
					curUpstream = ""
				}
			}
			stmt = nil
		case ";":
			if len(stmt) > 0 {
				d, args := stmt[0].s, stmt[1:]
				switch {
				case d == "server" && curUpstream != "" && len(args) > 0:
					if _, ok := upstreams[curUpstream]; !ok {
						upstreams[curUpstream] = args[0].s
					}
				case inServer() && d == "server_name":
					cur.line = stmt[0].line
					for _, a := range args {
						cur.names = append(cur.names, a.s)
					}
				case inServer() && d == "proxy_pass" && len(args) > 0:
					if locRoot() {
						if cur.proxy == "" {
							cur.proxy = args[0].s
						}
					} else if cur.locAny == "" {
						cur.locAny = args[0].s
					}
				case inServer() && locRoot() && (d == "auth_basic" || d == "auth_request") && len(args) > 0 && args[0].s != "off":
					if cur.auth == "" {
						cur.auth = d
					}
				}
			}
			stmt = nil
		default:
			stmt = append(stmt, t)
		}
	}
	return servers, upstreams
}

func nginxExposures(servers []nginxServer, upstreams map[string]string) []Exposure {
	byHost := map[string]*Exposure{}
	var order []string
	for _, s := range servers {
		raw := s.proxy
		if raw == "" {
			raw = s.locAny
		}
		var origin Origin
		if raw != "" && !strings.Contains(raw, "$") {
			o := ParseOrigin(raw)
			// proxy_pass http://backend; names an upstream block.
			if t, ok := upstreams[o.Host]; ok {
				o = ParseOrigin(t)
			}
			origin = o
		}
		for _, name := range s.names {
			name = strings.ToLower(name)
			if name == "_" || name == "" || strings.HasPrefix(name, "~") || strings.ContainsAny(name, "$") {
				continue
			}
			if name == "localhost" {
				continue
			}
			e := Exposure{Source: "nginx", Host: name, Origin: origin, Auth: s.auth != "", AuthBy: s.auth, File: s.file, Line: s.line}
			// The same host usually appears twice (80 redirect, 443 proxy).
			// Keep the server that actually has a backend, and let auth from
			// either one count.
			if prev, ok := byHost[name]; ok {
				if prev.Origin.IsZero() && !e.Origin.IsZero() {
					e.Auth, e.AuthBy = e.Auth || prev.Auth, firstNonEmpty(e.AuthBy, prev.AuthBy)
					*prev = e
				} else if !prev.Auth && e.Auth {
					prev.Auth, prev.AuthBy = true, e.AuthBy
				}
				continue
			}
			byHost[name] = &e
			order = append(order, name)
		}
	}
	var out []Exposure
	for _, h := range order {
		out = append(out, *byHost[h])
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

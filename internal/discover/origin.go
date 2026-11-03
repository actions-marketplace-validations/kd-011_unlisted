package discover

import (
	"net"
	"strconv"
	"strings"
)

// Origin is where a proxy or tunnel sends traffic.
type Origin struct {
	Raw    string
	Scheme string // http | https | tcp | ssh | unix | http_status | ...
	Host   string
	Port   int  // 0 when unknown or not applicable (unix sockets, static)
	Local  bool // the origin is this machine
}

// IsZero reports whether there is no backend (a static or redirect site).
func (o Origin) IsZero() bool { return o.Raw == "" }

// Addr is host:port for display.
func (o Origin) Addr() string {
	if o.Scheme == "unix" {
		return "unix:" + o.Host
	}
	if o.Scheme == "bastion" {
		return "bastion"
	}
	h := o.Host
	if h == "" {
		h = "localhost"
	}
	if o.Port == 0 {
		return h
	}
	return net.JoinHostPort(h, strconv.Itoa(o.Port))
}

// ParseOrigin reads the many spellings proxies use for a backend:
// http://localhost:8080, localhost:8080, :8080, [::1]:3000, unix:/run/x.sock,
// http_status:404.
func ParseOrigin(raw string) Origin {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	o := Origin{Raw: raw}
	if raw == "" {
		return o
	}
	switch {
	case strings.HasPrefix(raw, "unix:"):
		o.Scheme, o.Host, o.Local = "unix", strings.TrimPrefix(strings.TrimPrefix(raw, "unix:"), "//"), true
		return o
	case strings.HasPrefix(raw, "unix//"):
		// Caddy spells a socket unix//run/app.sock.
		o.Scheme, o.Host, o.Local = "unix", strings.TrimPrefix(raw, "unix/"), true
		return o
	case raw == "bastion":
		// cloudflared's built-in jump host: no port, nothing to check.
		o.Scheme = "bastion"
		return o
	case strings.HasPrefix(raw, "http_status:"), raw == "hello_world", raw == "hello-world":
		o.Scheme = "http_status"
		return o
	}

	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		o.Scheme, rest = strings.ToLower(rest[:i]), rest[i+3:]
	}
	if strings.HasPrefix(rest, "unix:") {
		// nginx: http://unix:/tmp/backend.socket:/uri/ (the socket, then a URI).
		sock := strings.TrimPrefix(rest, "unix:")
		if i := strings.Index(sock, ":"); i >= 0 {
			sock = sock[:i]
		}
		o.Scheme, o.Host, o.Local = "unix", sock, true
		return o
	}
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	host, port := rest, ""
	if h, p, err := net.SplitHostPort(rest); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
		host = strings.Trim(rest, "[]")
	}
	o.Host = strings.ToLower(host)
	if port != "" {
		o.Port, _ = strconv.Atoi(port)
	} else {
		switch o.Scheme {
		case "https":
			o.Port = 443
		case "ssh":
			o.Port = 22
		case "", "http":
			o.Port = 80
		}
	}
	o.Local = isLocalHost(o.Host)
	return o
}

func isLocalHost(h string) bool {
	switch h {
	case "", "localhost", "0.0.0.0", "::", "::1":
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

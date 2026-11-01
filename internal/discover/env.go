package discover

import (
	"os"
	"path/filepath"
	"strings"
)

// Env says where sources should look. With Root set, every default path is
// resolved underneath it, which is how the demo and the tests run against
// fixtures without touching the real machine.
type Env struct {
	Root string // "" means the real filesystem

	// Explicit overrides. These are literal paths and are not prefixed with Root.
	Cloudflared string
	Caddyfile   string
	NginxDir    string
	DockerSock  string

	Skip map[string]bool
}

// Path maps a virtual absolute path (/etc/caddy/Caddyfile) to a real one.
func (e Env) Path(virtual string) string {
	if e.Root == "" {
		return virtual
	}
	return filepath.Join(e.Root, virtual)
}

// Home is the home directory in virtual space. Under a fixture root there is
// no real home to read, so it is /root, where a service-run cloudflared lives.
func (e Env) Home() string {
	if e.Root != "" {
		return "/root"
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}

// resolve returns the virtual and real path for a candidate. Explicit
// overrides skip the root mapping.
func (e Env) resolve(override, virtual string) (shown, real string) {
	if override != "" {
		return override, override
	}
	return virtual, e.Path(virtual)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ParseSkip turns "docker,systemd" into a set.
func ParseSkip(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			out[p] = true
		}
	}
	return out
}

package discover

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Cloudflared reads tunnel ingress rules: hostname -> origin service.
type Cloudflared struct{}

func (Cloudflared) Name() string { return "cloudflared" }

func (Cloudflared) Discover(env Env) (Result, error) {
	var cands [][2]string
	if env.Cloudflared != "" {
		cands = append(cands, [2]string{env.Cloudflared, env.Cloudflared})
	} else {
		for _, v := range []string{"/etc/cloudflared/config.yml", "/etc/cloudflared/config.yaml", env.Home() + "/.cloudflared/config.yml"} {
			s, r := env.resolve("", v)
			cands = append(cands, [2]string{s, r})
		}
	}
	for _, c := range cands {
		b, err := os.ReadFile(c[1])
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return Result{}, fmt.Errorf("%s: %w", c[0], err)
		}
		res, err := ParseCloudflared(b, c[0])
		res.Paths = []string{c[0]}
		return res, err
	}
	return Result{}, ErrAbsent
}

// ParseCloudflared extracts ingress rules. It walks the YAML node tree rather
// than decoding into structs so every rule keeps its line number.
func ParseCloudflared(data []byte, file string) (Result, error) {
	res := Result{Unit: "rules"}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return res, fmt.Errorf("%s: %w", file, err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return res, nil
	}
	ingress := mapValue(doc.Content[0], "ingress")
	if ingress == nil || ingress.Kind != yaml.SequenceNode {
		return res, nil
	}
	for _, rule := range ingress.Content {
		hostKey, hostVal := mapEntry(rule, "hostname")
		_, svc := mapEntry(rule, "service")
		if hostVal == nil || svc == nil {
			continue // the catch-all rule has no hostname
		}
		host := strings.ToLower(strings.TrimSpace(hostVal.Value))
		if host == "" || host == "*" {
			continue
		}
		origin := ParseOrigin(svc.Value)
		res.Count++
		// http_status rules are deliberate blocks, not something being served.
		if origin.Scheme == "http_status" {
			continue
		}
		ex := Exposure{Source: "cloudflared", Host: host, Origin: origin, File: file, Line: hostKey.Line}
		// originRequest.access is cloudflared enforcing a Cloudflare Access
		// policy itself, the one auth signal a tunnel config can carry.
		if req := mapValue(rule, "originRequest"); req != nil {
			if acc := mapValue(req, "access"); acc != nil {
				if r := mapValue(acc, "required"); r != nil && r.Value == "true" {
					ex.Auth, ex.AuthBy = true, "originRequest.access"
				}
			}
		}
		res.Exposures = append(res.Exposures, ex)
	}
	return res, nil
}

// mapEntry returns the key and value nodes for key in a mapping node.
func mapEntry(n *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i], n.Content[i+1]
		}
	}
	return nil, nil
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	_, v := mapEntry(n, key)
	return v
}

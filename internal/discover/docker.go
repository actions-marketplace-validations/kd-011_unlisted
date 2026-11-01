package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// Docker lists published ports by talking HTTP to the Docker socket. No SDK:
// the one endpoint needed is GET /containers/json.
type Docker struct{}

func (Docker) Name() string { return "docker" }

type dockerContainer struct {
	Names []string
	Image string
	Ports []struct {
		IP          string
		PrivatePort int
		PublicPort  int
		Type        string
	}
}

func (Docker) Discover(env Env) (Result, error) {
	// A fixture root swaps the socket for a JSON file holding the same body the
	// API would return, so tests and the demo need no daemon.
	if env.Root != "" && env.DockerSock == "" {
		p := env.Path("/docker/containers.json")
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				return Result{}, ErrAbsent
			}
			return Result{}, err
		}
		res, err := ParseDocker(b)
		res.Paths = []string{"/docker/containers.json"}
		return res, err
	}

	sock, _ := env.resolve(env.DockerSock, "/var/run/docker.sock")
	if _, err := os.Stat(sock); err != nil {
		if os.IsNotExist(err) {
			return Result{}, ErrAbsent
		}
		if errors.Is(err, os.ErrPermission) {
			return Result{}, fmt.Errorf("%s: permission denied (add the user to the docker group, or run as root)", sock)
		}
		return Result{}, err
	}
	cli := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	resp, err := cli.Get("http://docker/containers/json")
	if err != nil {
		if errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), "permission denied") {
			return Result{}, fmt.Errorf("%s: permission denied (add the user to the docker group, or run as root)", sock)
		}
		return Result{}, fmt.Errorf("docker socket: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("docker socket answered %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return Result{}, err
	}
	res, err := ParseDocker(b)
	res.Paths = []string{sock}
	return res, err
}

// ParseDocker turns an API response into listeners. Only published ports
// matter: an unpublished container port is not exposed by definition.
func ParseDocker(body []byte) (Result, error) {
	var cs []dockerContainer
	if err := json.Unmarshal(body, &cs); err != nil {
		return Result{}, fmt.Errorf("docker response: %w", err)
	}
	res := Result{Unit: "containers", Count: len(cs)}
	for _, c := range cs {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		for _, p := range c.Ports {
			if p.PublicPort == 0 || p.Type != "tcp" {
				continue
			}
			addr := p.IP
			if addr == "" {
				addr = "0.0.0.0"
			}
			ip := net.ParseIP(addr)
			res.Listeners = append(res.Listeners, Listener{
				Port: p.PublicPort, Addr: addr,
				Public:    ip == nil || !ip.IsLoopback(),
				Container: name, Image: c.Image, ContainerPort: p.PrivatePort,
				Sources: []string{"docker"},
			})
		}
	}
	return res, nil
}

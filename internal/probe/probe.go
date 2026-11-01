// Package probe is the only code in unlisted that touches the network, and it
// only runs under --probe. It contacts the hostnames in the registry, nothing
// else.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Result is what one host answered.
type Result struct {
	Host     string `json:"host"`
	Status   int    `json:"status,omitempty"`
	Err      string `json:"error,omitempty"`
	Millis   int64  `json:"ms,omitempty"`
	CertDays *int   `json:"cert_days_left,omitempty"`
	CertErr  string `json:"cert_error,omitempty"`
	// AuthHint is set when the response itself shows a login in front:
	// cloudflare-access | http-auth | login-redirect.
	AuthHint string `json:"auth_hint,omitempty"`
}

// OK reports whether anything answered at all.
func (r Result) OK() bool { return r.Err == "" }

// Dead reports a failure that means nothing is serving the host: no transport
// connection, or the gateway answering that its backend is gone.
func (r Result) Dead() bool {
	return r.Err != "" || r.Status == 502 || r.Status == 503 || r.Status == 504
}

// Options controls a probe run.
type Options struct {
	Timeout time.Duration
	// Dial overrides how hosts are reached; tests point it at a local server.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time
}

// Hosts probes every host concurrently, in a stable order.
func Hosts(hosts []string, opt Options) []Result {
	if opt.Timeout == 0 {
		opt.Timeout = 5 * time.Second
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	out := make([]Result, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = one(h, opt)
		}(i, h)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func one(host string, opt Options) Result {
	res := Result{Host: host}
	var leaf *x509.Certificate
	var verifyErr error

	tr := &http.Transport{
		DialContext:         opt.Dial,
		TLSHandshakeTimeout: opt.Timeout,
		// Verification is done by hand so an expired or self-signed cert is
		// reported as a finding instead of hiding the response behind an error.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return nil
				}
				leaf = cs.PeerCertificates[0]
				pool := x509.NewCertPool()
				for _, c := range cs.PeerCertificates[1:] {
					pool.AddCert(c)
				}
				_, verifyErr = leaf.Verify(x509.VerifyOptions{
					DNSName: host, Intermediates: pool, CurrentTime: opt.Now(),
				})
				return nil
			},
		},
		DisableKeepAlives: true,
	}
	cli := &http.Client{
		Timeout:   opt.Timeout,
		Transport: tr,
		// A 302 to a login page is proof the service answered. Following it
		// would only wander off the host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	start := time.Now()
	resp, err := do(cli, http.MethodHead, host)
	if err == nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		resp.Body.Close()
		resp, err = do(cli, http.MethodGet, host)
	}
	res.Millis = time.Since(start).Milliseconds()
	if err != nil {
		res.Err = shortErr(err)
	} else {
		defer resp.Body.Close()
		res.Status = resp.StatusCode
		res.AuthHint = authHint(resp)
	}
	if leaf != nil {
		days := int(leaf.NotAfter.Sub(opt.Now()).Hours() / 24)
		if leaf.NotAfter.Before(opt.Now()) {
			days = -int(opt.Now().Sub(leaf.NotAfter).Hours()/24) - 1
		}
		res.CertDays = &days
		if verifyErr != nil {
			res.CertErr = verifyErr.Error()
		}
	}
	return res
}

func do(cli *http.Client, method, host string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, "https://"+host+"/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "unlisted-probe/1")
	return cli.Do(req)
}

func authHint(r *http.Response) string {
	loc := strings.ToLower(r.Header.Get("Location"))
	switch {
	case strings.Contains(loc, "cloudflareaccess.com"):
		return "cloudflare-access"
	case (r.StatusCode == 401 || r.StatusCode == 403) && r.Header.Get("WWW-Authenticate") != "":
		return "http-auth"
	case r.StatusCode >= 300 && r.StatusCode < 400:
		for _, w := range []string{"login", "signin", "sign-in", "auth", "sso", "oauth", "authelia", "authentik"} {
			if strings.Contains(loc, w) {
				return "login-redirect"
			}
		}
	}
	return ""
}

// shortErr trims Go's nested transport errors to something that fits a line.
func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return "DNS does not resolve"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "deadline exceeded"), strings.Contains(s, "Timeout"), strings.Contains(s, "timeout"):
		return "timed out"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

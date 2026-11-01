package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// dialTo sends every connection to addr, whatever hostname was asked for, so
// tests can probe "app.example.com" without any DNS.
func dialTo(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

// server starts a TLS server whose certificate is valid for host, signed by a
// throwaway CA that the probe does not trust, expiring after life.
func server(t *testing.T, host string, life time.Duration, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host},
		DNSNames:  []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func probeOne(srv *httptest.Server, host string) Result {
	return Hosts([]string{host}, Options{Timeout: 3 * time.Second, Dial: dialTo(srv.Listener.Addr().String())})[0]
}

func TestStatusAndCertDays(t *testing.T) {
	srv := server(t, "app.example.com", 5*24*time.Hour+time.Hour, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	})
	r := probeOne(srv, "app.example.com")
	if r.Err != "" || r.Status != 204 {
		t.Fatalf("%+v", r)
	}
	if r.CertDays == nil || *r.CertDays != 5 {
		t.Errorf("cert days = %v", r.CertDays)
	}
	// Self-signed, so verification must fail, without hiding the response.
	if r.CertErr == "" {
		t.Error("untrusted cert should be reported")
	}
}

func TestExpiredCert(t *testing.T) {
	srv := server(t, "app.example.com", -48*time.Hour, func(w http.ResponseWriter, r *http.Request) {})
	// A cert whose NotBefore is after NotAfter is odd, but the probe only needs
	// to see it is in the past.
	r := probeOne(srv, "app.example.com")
	if r.CertDays == nil || *r.CertDays >= 0 {
		t.Fatalf("expired cert days = %v", r.CertDays)
	}
}

func TestHeadFallsBackToGet(t *testing.T) {
	var methods []string
	srv := server(t, "app.example.com", 90*24*time.Hour, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(200)
	})
	r := probeOne(srv, "app.example.com")
	if r.Status != 200 || len(methods) != 2 || methods[1] != "GET" {
		t.Fatalf("status %d methods %v", r.Status, methods)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	srv := server(t, "app.example.com", 90*24*time.Hour, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://team.cloudflareaccess.com/cdn-cgi/access/login/app.example.com")
		w.WriteHeader(302)
	})
	r := probeOne(srv, "app.example.com")
	if r.Status != 302 || r.AuthHint != "cloudflare-access" {
		t.Fatalf("%+v", r)
	}
}

func TestAuthHints(t *testing.T) {
	cases := []struct {
		status int
		hdr    map[string]string
		want   string
	}{
		{401, map[string]string{"WWW-Authenticate": `Basic realm="x"`}, "http-auth"},
		{302, map[string]string{"Location": "https://auth.example.com/?rd=x"}, "login-redirect"},
		{302, map[string]string{"Location": "/dashboard"}, ""},
		{200, nil, ""},
		{401, nil, ""},
	}
	for _, c := range cases {
		resp := &http.Response{StatusCode: c.status, Header: http.Header{}}
		for k, v := range c.hdr {
			resp.Header.Set(k, v)
		}
		if got := authHint(resp); got != c.want {
			t.Errorf("%d %v -> %q, want %q", c.status, c.hdr, got, c.want)
		}
	}
}

func TestTransportFailureIsDead(t *testing.T) {
	r := Hosts([]string{"down.example.com"}, Options{
		Timeout: time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial tcp 10.0.0.1:443: connect: connection refused")
		},
	})[0]
	if r.Err != "connection refused" || !r.Dead() || r.OK() {
		t.Fatalf("%+v", r)
	}
}

func TestGatewayErrorsAreDead(t *testing.T) {
	for code, dead := range map[int]bool{502: true, 503: true, 504: true, 500: false, 404: false, 200: false} {
		if got := (Result{Status: code}).Dead(); got != dead {
			t.Errorf("%d dead=%v", code, got)
		}
	}
}

func TestResultsAreSortedAndConcurrent(t *testing.T) {
	srv := server(t, "x.example.com", 90*24*time.Hour, func(w http.ResponseWriter, r *http.Request) {})
	hosts := []string{"c.example.com", "a.example.com", "b.example.com"}
	rs := Hosts(hosts, Options{Timeout: 3 * time.Second, Dial: dialTo(srv.Listener.Addr().String())})
	if len(rs) != 3 || rs[0].Host != "a.example.com" || rs[2].Host != "c.example.com" {
		t.Fatalf("%+v", rs)
	}
}

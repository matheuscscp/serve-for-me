package serveforme_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2/google"

	serveforme "github.com/matheuscscp/serve-for-me"
)

func TestEndToEnd(t *testing.T) {
	g := NewWithT(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	oidcServer, allowedIdentities, idToken, expiredToken := newOIDCServer(g)
	defer oidcServer.Close()

	h, err := serveforme.NewServer(allowedIdentities,
		serveforme.WithOIDCClient(oidcServer.Client()))
	g.Expect(err).NotTo(HaveOccurred())

	s := httptest.NewTLSServer(h)
	defer s.Close()
	client := s.Client()

	for _, tt := range []struct {
		name    string
		idToken string
	}{
		{
			name:    "invalid token",
			idToken: "invalid-token",
		},
		{
			name:    "expired token",
			idToken: expiredToken,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			invalidStarted := make(chan struct{})
			defer close(invalidStarted)

			err = serveforme.ServeForMe(ctx, s.URL, invalidStarted, map[string]http.Handler{},
				serveforme.WithIDToken(tt.idToken),
				serveforme.WithHTTPClient(client))
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(
				"failed to WebSocket dial: expected handshake response status code 101 but got 401"))
		})
	}

	type testCase struct {
		name string
		opts []serveforme.ClientOption
	}

	testCases := []testCase{
		{
			name: "generic OIDC token",
			opts: []serveforme.ClientOption{serveforme.WithIDToken(idToken)},
		},
		// Test deregistration and serving again with the same token.
		{
			name: "deregistration and serve again",
			opts: []serveforme.ClientOption{serveforme.WithIDToken(idToken)},
		},
	}
	if hasGitHubActions() {
		testCases = append(testCases, testCase{
			name: "GitHub Actions token",
			opts: []serveforme.ClientOption{serveforme.WithGitHubActions()},
		})
	}
	if hasGoogleIDToken() {
		testCases = append(testCases, testCase{
			name: "Google ID token",
			opts: []serveforme.ClientOption{serveforme.WithGoogleIDToken()},
		})
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			started := make(chan struct{})
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				err := serveforme.ServeForMe(ctx, s.URL, started, map[string]http.Handler{
					"GET /foo": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusAccepted)
						w.Write([]byte("foo response"))
					}),
					"POST /bar": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						b, err := io.ReadAll(r.Body)
						g.Expect(err).NotTo(HaveOccurred())
						w.WriteHeader(http.StatusCreated)
						w.Write([]byte("bar response " + string(b)))
					}),
				}, append(tt.opts, serveforme.WithHTTPClient(client))...)
				g.Expect(err).NotTo(HaveOccurred())
			}()
			select {
			case <-ctx.Done():
				t.Fatal("context timed out before server started")
			case <-started:
			}

			for _, ttt := range []struct {
				name       string
				method     string
				path       string
				body       string
				respStatus int
				respBody   string
			}{
				{
					name:       "GET foo",
					method:     http.MethodGet,
					path:       "/foo",
					respStatus: http.StatusAccepted,
					respBody:   "foo response",
				},
				{
					name:       "POST bar",
					method:     http.MethodPost,
					path:       "/bar",
					respStatus: http.StatusCreated,
					body:       "test data",
					respBody:   "bar response test data",
				},
				{
					name:       "not found",
					method:     http.MethodGet,
					path:       "/some-path",
					respStatus: http.StatusNotFound,
					respBody:   "Backend not found\n",
				},
			} {
				t.Run(ttt.name, func(t *testing.T) {
					g := NewWithT(t)

					body := strings.NewReader(ttt.body)

					req, err := http.NewRequestWithContext(ctx, ttt.method, s.URL+ttt.path, body)
					g.Expect(err).NotTo(HaveOccurred())

					resp, err := client.Do(req)
					g.Expect(err).NotTo(HaveOccurred())
					defer resp.Body.Close()

					g.Expect(resp.StatusCode).To(Equal(ttt.respStatus))
					respBody, err := io.ReadAll(resp.Body)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(string(respBody)).To(Equal(ttt.respBody))
				})
			}

			cancel()
			select {
			case <-time.After(5 * time.Second):
				t.Fatal("server did not stop after context cancellation")
			case <-stopped:
			}
		})
	}
}

func newOIDCServer(g *WithT) (*httptest.Server, []serveforme.Identity, string, string) {
	const (
		issuerPath = "/.well-known/openid-configuration"
		jwksPath   = "/openid/v1/jwks"
		algo       = jwa.RS256
		aud        = "test-audience"
		sub        = "test-subject"
	)

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	g.Expect(err).NotTo(HaveOccurred())

	jpk, err := jwk.FromRaw(pk)
	g.Expect(err).NotTo(HaveOccurred())

	jpub, err := jpk.PublicKey()
	g.Expect(err).NotTo(HaveOccurred())

	var s *httptest.Server
	s = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case issuerPath:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := fmt.Sprintf(`{
				"issuer": "%s",
				"jwks_uri": "%s",
				"id_token_signing_alg_values_supported": ["%s"]
			}`, s.URL, s.URL+jwksPath, algo.String())
			w.Write([]byte(resp))
		case jwksPath:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(map[string]any{"keys": []jwk.Key{jpub}})
			g.Expect(err).NotTo(HaveOccurred())
		}
	}))

	allowedIdentities := []serveforme.Identity{{
		Issuer:   s.URL,
		ClientID: aud,
		Subject:  sub,
	}}
	if hasGitHubActions() {
		id, err := serveforme.NewIdentityFromTokenSource(context.Background(), serveforme.GitHubActions{})
		g.Expect(err).NotTo(HaveOccurred())
		allowedIdentities = append(allowedIdentities, *id)
	}
	if hasGoogleIDToken() {
		id, err := serveforme.NewIdentityFromTokenSource(context.Background(), serveforme.GoogleIDToken{})
		g.Expect(err).NotTo(HaveOccurred())
		allowedIdentities = append(allowedIdentities, *id)
	}

	now := time.Now()
	exp := now.Add(time.Minute)
	nbf := now
	iat := now

	tok, err := jwt.NewBuilder().
		Issuer(s.URL).
		Subject(sub).
		Audience([]string{aud}).
		Expiration(exp).
		NotBefore(nbf).
		IssuedAt(iat).
		Build()
	g.Expect(err).NotTo(HaveOccurred())

	idToken, err := jwt.Sign(tok, jwt.WithKey(algo, jpk))
	g.Expect(err).NotTo(HaveOccurred())

	expTok, err := jwt.NewBuilder().
		Issuer(s.URL).
		Subject(sub).
		Audience([]string{aud}).
		Expiration(time.Time{}).
		NotBefore(nbf).
		IssuedAt(iat).
		Build()
	g.Expect(err).NotTo(HaveOccurred())

	expiredToken, err := jwt.Sign(expTok, jwt.WithKey(algo, jpk))
	g.Expect(err).NotTo(HaveOccurred())

	// Merge system cert pool with the server's certificate to support also public CA certificates.
	pool, err := x509.SystemCertPool()
	g.Expect(err).NotTo(HaveOccurred())
	pool.AddCert(s.Certificate())
	s.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs = pool

	return s, allowedIdentities, string(idToken), string(expiredToken)
}

func hasGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

func hasGoogleIDToken() bool {
	creds, err := google.FindDefaultCredentials(context.Background())
	return err == nil && creds != nil
}

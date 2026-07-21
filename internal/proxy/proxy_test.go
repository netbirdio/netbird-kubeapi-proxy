// SPDX-License-Identifier: AGPL-3.0

package proxy

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-openapi/testify/v2/require"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

type mockPeerLister struct{}

func (p *mockPeerLister) List(ctx context.Context, opts ...netbird.PeersListOption) ([]api.Peer, error) {
	peers := map[string]api.Peer{
		"192.0.2.1": {
			UserId: "foo",
			Groups: []api.GroupMinimum{
				{
					Name: "group1",
				},
				{
					Name: "group2",
				},
			},
		},
	}

	ip := ""
	for _, o := range opts {
		k, v := o()
		if k == "ip" {
			ip = v
			break
		}
	}
	if ip != "" {
		peer, ok := peers[ip]
		if !ok {
			return nil, nil
		}
		return []api.Peer{peer}, nil
	}
	return nil, nil
}

func TestProxyHandler(t *testing.T) {
	t.Parallel()

	peerStore := NewPeerStore(&mockPeerLister{})

	bearerToken := "foobar"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
		if token != bearerToken {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		// The API server serves /openapi/v2 and /openapi/v3 only at their
		// exact paths, so any trailing-slash redirect by the proxy results
		// in a 404 here, just like against a real API server.
		switch req.URL.Path {
		case "/version", "/openapi/v2", "/openapi/v3":
		default:
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		body := fmt.Sprintf("%s %s %s", req.Header[AuthorizationHeader], req.Header[ImpersonateUserHeader], req.Header[ImpersonateGroupHeader])
		// nolint: errcheck
		rw.Write([]byte(body))
	}))
	t.Cleanup(func() {
		srv.Close()
	})
	certPool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	// Intentionally parse the URL without a trailing slash so that the
	// target has an empty path. This guards against a regression where an
	// empty-path location caused UpgradeAwareHandler to 301-redirect every
	// GET/HEAD to its trailing-slash form, breaking exact-path endpoints
	// such as /openapi/v2 (see https://issue.k8s.io/4958).
	kubeAPIServerURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	tests := []struct {
		name           string
		path           string
		remoteAddr     string
		headers        map[string]string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "valid peer",
			path:           "/version",
			headers:        nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "[Bearer foobar] [foo] [group1 group2]",
		},
		{
			name: "valid peer with bearer token",
			path: "/version",
			headers: map[string]string{
				AuthorizationHeader: "Bearer testtest",
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "[Bearer foobar] [foo] [group1 group2]",
		},
		{
			name:           "openapi v2 is proxied without trailing-slash redirect",
			path:           "/openapi/v2",
			headers:        nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "[Bearer foobar] [foo] [group1 group2]",
		},
		{
			name:           "openapi v3 is proxied without trailing-slash redirect",
			path:           "/openapi/v3",
			headers:        nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "[Bearer foobar] [foo] [group1 group2]",
		},
		{
			name:           "no peer found",
			path:           "/version",
			remoteAddr:     "192.0.2.2:123",
			headers:        nil,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil)
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			for k, v := range tt.headers {
				req.Header.Add(k, v)
			}
			rec := httptest.NewRecorder()
			handler := proxyHandler(peerStore, kubeAPIServerURL, certPool, bearerToken)
			handler(rec, req)
			b, err := io.ReadAll(rec.Result().Body)
			require.NoError(t, err)

			require.EqualT(t, tt.expectedStatus, rec.Result().StatusCode)
			require.EqualT(t, tt.expectedBody, string(b))
		})
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	t.Parallel()

	fqdn := "example.com"
	tlsCert, err := generateSelfSignedCert(fqdn)
	require.NoError(t, err)
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)
	require.Len(t, x509Cert.DNSNames, 1)
	require.EqualT(t, fqdn, x509Cert.DNSNames[0])
}

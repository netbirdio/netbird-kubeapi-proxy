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

type mockPeerLister struct {
	peers map[string]api.Peer
}

func (p *mockPeerLister) List(ctx context.Context, opts ...netbird.PeersListOption) ([]api.Peer, error) {
	ip := ""
	for _, o := range opts {
		k, v := o()
		if k == "ip" {
			ip = v
			break
		}
	}
	if ip != "" {
		peer, ok := p.peers[ip]
		if !ok {
			return nil, nil
		}
		return []api.Peer{peer}, nil
	}
	return nil, nil
}

func TestProxyHandler(t *testing.T) {
	t.Parallel()

	peerLister := &mockPeerLister{
		peers: map[string]api.Peer{
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
		},
	}

	bearerToken := "foobar"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		token, _ := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
		if token != bearerToken {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		if req.URL.Path != "/version" {
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
	kubeAPIServerURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	tests := []struct {
		name           string
		remoteAddr     string
		headers        map[string]string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "valid peer",
			headers:        nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "[Bearer foobar] [foo] [group1 group2]",
		},
		{
			name: "valid peer with bearer token",
			headers: map[string]string{
				AuthorizationHeader: "Bearer testtest",
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "[Bearer foobar] [foo] [group1 group2]",
		},
		{
			name:           "no peer found",
			remoteAddr:     "192.0.2.2:123",
			headers:        nil,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/version", nil)
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			for k, v := range tt.headers {
				req.Header.Add(k, v)
			}
			rec := httptest.NewRecorder()
			handler := proxyHandler(peerLister, kubeAPIServerURL, certPool, bearerToken)
			handler(rec, req)
			b, err := io.ReadAll(rec.Result().Body)
			require.NoError(t, err)

			require.EqualT(t, tt.expectedStatus, rec.Result().StatusCode)
			require.EqualT(t, tt.expectedBody, string(b))
		})
	}
}

func TestProxyHandlerPreservesUpgrade(t *testing.T) {
	t.Parallel()

	peerLister := &mockPeerLister{
		peers: map[string]api.Peer{
			"192.0.2.1": {
				UserId: "foo",
				Groups: []api.GroupMinimum{
					{
						Name: "group1",
					},
				},
			},
		},
	}

	bearerToken := "foobar"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Echo the headers that reached the API server so the test can
		// assert the upgrade handshake survived and identity is the peer's.
		body := fmt.Sprintf("%s %s %s %s",
			req.Header.Get(ConnectionHeader),
			req.Header.Get(UpgradeHeader),
			req.Header.Get(SecWebsocketKeyHeader),
			req.Header.Get(ImpersonateUserHeader),
		)
		// nolint: errcheck
		rw.Write([]byte(body))
	}))
	t.Cleanup(func() {
		srv.Close()
	})
	certPool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	kubeAPIServerURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/namespaces/default/pods/example/exec", nil)
	req.Header.Set(ConnectionHeader, "Upgrade")
	req.Header.Set(UpgradeHeader, "websocket")
	req.Header.Set(SecWebsocketKeyHeader, "dGhlIHNhbXBsZSBub25jZQ==")
	// A client must not be able to impersonate by sending this directly.
	req.Header.Set(ImpersonateUserHeader, "system:admin")
	rec := httptest.NewRecorder()

	handler := proxyHandler(peerLister, kubeAPIServerURL, certPool, bearerToken)
	handler(rec, req)

	b, err := io.ReadAll(rec.Result().Body)
	require.NoError(t, err)
	require.EqualT(t, http.StatusOK, rec.Result().StatusCode)
	require.EqualT(t, "Upgrade websocket dGhlIHNhbXBsZSBub25jZQ== foo", string(b))
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

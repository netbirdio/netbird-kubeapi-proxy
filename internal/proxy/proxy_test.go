// SPDX-License-Identifier: BSD-3-Clause

package proxy

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
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
			return nil, fmt.Errorf("peer with ip %s could not be found", ip)
		}
		return []api.Peer{peer}, nil
	}
	return nil, nil
}

func TestRewriteHandler(t *testing.T) {
	t.Parallel()

	peerLister := &mockPeerLister{
		peers: map[string]api.Peer{
			"192.0.2.1": {
				UserId: "foo",
				Groups: []api.GroupMinimum{
					{
						Name: "bar",
					},
				},
			},
		},
	}

	serverURL, err := url.Parse("https://internal.name")
	require.NoError(t, err)
	bearerToken := "foobar"
	handler := rewriteHandler(peerLister, serverURL, bearerToken)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/version", nil)
	pr := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(t.Context()),
	}
	handler(pr)

	require.EqualT(t, "example.com", pr.In.Host)
	require.EqualT(t, "https://internal.name/version", pr.Out.URL.String())
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

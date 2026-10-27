// SPDX-License-Identifier: AGPL-3.0

//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	// peerUserPrefix is how the proxy names a peer that has no NetBird user,
	// such as one added with a setup key.
	peerUserPrefix = "netbird:peer:"

	selfSubjectReviewPath = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
	selfSubjectReview     = `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`
	kubeSystemPath        = "/api/v1/namespaces/kube-system"
)

// reportedVersion is what the Makefile stamps for the peer: the NetBird release
// as the semver core, the proxy release as build metadata.
var reportedVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\+kubeapi-proxy\.`)

func TestProxyPeer(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)

	assert.True(t, e.proxyPeer.Connected, "the proxy peer should be connected")
	// Management gates features on the NetBird release leading this string, so a
	// proxy reporting "development" or its own release first would lose them.
	assert.Regexp(t, reportedVersion, e.proxyPeer.Version, "the proxy should report the NetBird release it embeds, with its own as build metadata")
}

// TestImpersonation checks the identity the API server sees for a request
// through the proxy: the peer, and the names of its NetBird groups.
func TestImpersonation(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)

	info := whoAmI(t, e, e.reader)
	assert.Equal(t, peerUserPrefix+e.reader.id, info.Username, "the API server should see the reader peer")
	assert.Contains(t, info.Groups, readerGroup, "the reader's NetBird group should be impersonated")
	assert.Contains(t, info.Groups, "All", "every NetBird group should be impersonated, All included")

	info = whoAmI(t, e, e.outsider)
	assert.Equal(t, peerUserPrefix+e.outsider.id, info.Username, "the API server should see the outsider peer")
	assert.NotContains(t, info.Groups, readerGroup, "the outsider is not in the reader group")
}

// TestGroupAuthorization checks that RBAC bound to a NetBird group name decides
// what a peer may do through the proxy.
func TestGroupAuthorization(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)

	resp, err := e.get(t.Context(), e.reader, kubeSystemPath)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.status, "the reader group may read namespaces")
	var ns corev1.Namespace
	require.NoError(t, json.Unmarshal([]byte(resp.body), &ns), "decode namespace %q", resp.body)
	assert.Equal(t, "kube-system", ns.Name, "the reader should get the namespace back")

	resp, err = e.get(t.Context(), e.outsider, kubeSystemPath)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.status, "a peer outside the reader group may not read namespaces")
}

// TestCallerCannotChooseIdentity checks that the proxy drops credentials and
// impersonation headers a peer sends, so a peer cannot claim another identity.
func TestCallerCannotChooseIdentity(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)

	forged := []string{
		"Impersonate-User: system:admin",
		"Impersonate-Group: system:masters",
		"Authorization: Bearer forged",
	}
	resp, err := e.post(t.Context(), e.outsider, selfSubjectReviewPath, selfSubjectReview, forged...)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.status, "a SelfSubjectReview should be created")
	info := decodeUserInfo(t, resp.body)
	assert.Equal(t, peerUserPrefix+e.outsider.id, info.Username, "a forged Impersonate-User should be ignored")
	assert.NotContains(t, info.Groups, "system:masters", "a forged Impersonate-Group should be ignored")

	resp, err = e.get(t.Context(), e.outsider, kubeSystemPath, forged...)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.status, "forged headers should not grant access")
}

// TestDiscoveryPaths checks that discovery endpoints answer directly. Some
// clients, kube-rs among them, do not follow a redirect to the trailing-slash
// form.
func TestDiscoveryPaths(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)

	for _, path := range []string{"/api", "/apis", "/version", "/openapi/v2", "/openapi/v3"} {
		resp, err := e.get(t.Context(), e.outsider, path)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.status, "GET %s should be answered without a redirect", path)
	}
}

// TestUnproxiedPaths checks that only the API prefixes reach the API server.
func TestUnproxiedPaths(t *testing.T) {
	t.Parallel()
	e := requireEnv(t)

	for _, path := range []string{"/healthz", "/livez", "/metrics", "/"} {
		resp, err := e.get(t.Context(), e.reader, path)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.status, "GET %s should not be proxied", path)
	}
}

// whoAmI returns the user the API server sees for a request from peer.
func whoAmI(t *testing.T, e *environment, peer *outsidePeer) authenticationv1.UserInfo {
	t.Helper()
	resp, err := e.post(t.Context(), peer, selfSubjectReviewPath, selfSubjectReview)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.status, "a SelfSubjectReview from %s should be created", peer.client.Hostname())
	return decodeUserInfo(t, resp.body)
}

func decodeUserInfo(t *testing.T, body string) authenticationv1.UserInfo {
	t.Helper()
	var review authenticationv1.SelfSubjectReview
	require.NoError(t, json.Unmarshal([]byte(body), &review), "decode SelfSubjectReview %q", body)
	return review.Status.UserInfo
}

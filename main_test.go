// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
)

func TestManagementClientUserAgent(t *testing.T) {
	t.Parallel()

	var gotUserAgent, gotAuthorization string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUserAgent = req.UserAgent()
		gotAuthorization = req.Header.Get("Authorization")
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)

	_, err := newManagementClient(srv.URL, "nbp_test").Peers.List(t.Context())
	require.NoError(t, err)

	want := "netbird-kubeapi-proxy/development (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
	assert.Equal(t, want, gotUserAgent, "management requests should identify the proxy and its version")
	assert.Equal(t, "Bearer nbp_test", gotAuthorization, "the API key should still be sent")
}

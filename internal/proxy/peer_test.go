// SPDX-License-Identifier: AGPL-3.0

package proxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestPeerStoreEviction(t *testing.T) {
	t.Parallel()

	peerStore := NewPeerStore(nil)
	peerStore.cache["foo"] = api.Peer{}
	peerStore.lastUpdated["foo"] = time.Now()

	peerStore.evictCache()
	require.Len(t, peerStore.cache, 1)
	require.Len(t, peerStore.lastUpdated, 1)

	for i := range 100 {
		peerStore.cache[fmt.Sprintf("%d", i)] = api.Peer{}
		peerStore.lastUpdated[fmt.Sprintf("%d", i)] = time.Now().Add(-time.Minute)
	}
	require.Len(t, peerStore.cache, 101)
	require.Len(t, peerStore.lastUpdated, 101)

	_, err := peerStore.Get(t.Context(), "foo")
	require.NoError(t, err)
	require.Len(t, peerStore.cache, 1)
	require.Len(t, peerStore.lastUpdated, 1)
}

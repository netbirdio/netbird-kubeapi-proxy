// SPDX-License-Identifier: AGPL-3.0

package proxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/require"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func writeToken(t *testing.T, path, token string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(token), 0o600))
}

func TestFileTokenSourceRereadsTheFileOncePerPeriod(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, "first")
	clock := &fakeClock{now: time.Now()}
	tokens, err := newFileTokenSource(path, clock.Now)
	require.NoError(t, err)

	writeToken(t, path, "second")
	token, err := tokens.Token()
	require.NoError(t, err)
	require.EqualT(t, "first", token)

	clock.now = clock.now.Add(tokenRereadPeriod)
	token, err = tokens.Token()
	require.NoError(t, err)
	require.EqualT(t, "second", token)
}

func TestFileTokenSourceKeepsTheLastTokenWhenARereadFails(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, "first")
	clock := &fakeClock{now: time.Now()}
	tokens, err := newFileTokenSource(path, clock.Now)
	require.NoError(t, err)

	tests := []struct {
		name    string
		corrupt func()
	}{
		{name: "file removed", corrupt: func() { require.NoError(t, os.Remove(path)) }},
		{name: "file empty", corrupt: func() { writeToken(t, path, "") }},
	}
	for _, tt := range tests {
		tt.corrupt()
		clock.now = clock.now.Add(tokenRereadPeriod)
		token, err := tokens.Token()
		require.NoError(t, err, tt.name)
		require.EqualT(t, "first", token, tt.name)
	}
}

func TestNewFileTokenSourceRefusesAMissingOrEmptyToken(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	writeToken(t, empty, " \n")

	for _, path := range []string{filepath.Join(dir, "missing"), empty} {
		_, err := newFileTokenSource(path, time.Now)
		require.Error(t, err, path)
	}
}

func TestFileTokenSourceTrimsTheToken(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, "first\n")
	tokens, err := newFileTokenSource(path, time.Now)
	require.NoError(t, err)

	token, err := tokens.Token()
	require.NoError(t, err)
	require.EqualT(t, "first", token)
}

// SPDX-License-Identifier: AGPL-3.0

package proxy

import (
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// The kubelet rotates a projected ServiceAccount token on disk, so the file is
// re-read at the same interval client-go uses for in-cluster clients:
// https://github.com/kubernetes/client-go/blob/v0.37.1/transport/token_source.go#L69-L81
const tokenRereadPeriod = time.Minute

type tokenSource interface {
	Token() (string, error)
}

// fileTokenSource reads a bearer token from a file at most once per tokenRereadPeriod.
// When a re-read fails it keeps returning the last token it read.
type fileTokenSource struct {
	path string
	now  func() time.Time

	mu     sync.Mutex
	token  string
	readAt time.Time
}

// newFileTokenSource reads the token once, so a missing or empty file fails at
// startup rather than on the first proxied request.
func newFileTokenSource(path string, now func() time.Time) (*fileTokenSource, error) {
	ts := &fileTokenSource{path: path, now: now}
	if _, err := ts.Token(); err != nil {
		return nil, err
	}
	return ts, nil
}

func (ts *fileTokenSource) Token() (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := ts.now()
	if ts.token != "" && now.Sub(ts.readAt) < tokenRereadPeriod {
		return ts.token, nil
	}
	token, err := readToken(ts.path)
	if err != nil {
		if ts.token == "" {
			return "", err
		}
		slog.Default().Warn("could not re-read the service account token, using the previous one", "path", ts.path, "error", err)
		return ts.token, nil
	}
	ts.token = token
	ts.readAt = now
	return token, nil
}

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errors.New("token cannot be empty")
	}
	return token, nil
}

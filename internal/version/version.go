// SPDX-License-Identifier: AGPL-3.0

// Package version identifies the proxy release a binary was built as.
package version

import (
	"fmt"
	"runtime"
)

// version is the proxy release, stamped by the Makefile through -ldflags -X.
var version = "development"

// Version returns the proxy release this binary was built as, or "development"
// when the build did not stamp one.
func Version() string {
	return version
}

// UserAgent returns the User-Agent the proxy sends to the NetBird management
// API, so its requests can be told apart from other API clients and tied to a
// release.
func UserAgent() string {
	return fmt.Sprintf("netbird-kubeapi-proxy/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

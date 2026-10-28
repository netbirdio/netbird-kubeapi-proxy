// SPDX-License-Identifier: AGPL-3.0

//go:build e2e

// Package e2e runs the proxy in a Kubernetes cluster against a NetBird
// deployment that the suite starts itself, so it needs nothing but Docker and Go:
//
//	make test-e2e
//
// The deployment comes from NetBird's own e2e harness at the revision pinned in
// go.mod, which builds the server and the client from that revision's source.
// The proxy is installed from this repository's manifests into a Kind cluster
// running on the deployment's Docker network, the only place its management
// address resolves. Peers outside the cluster, in harness containers, then reach
// the Kubernetes API through the proxy over NetBird, and the tests check what
// the API server sees them as. Nothing is written into the management store: the
// account comes from POST /api/setup and every fixture from the public API.
//
// Environment knobs:
//
//	IMG_REF                 the proxy image under test, set by make test-e2e
//	NB_E2E_KIND_NODE_IMAGE  the Kind node image, which picks the Kubernetes version
//	NB_E2E_KEEP             leave the cluster and the deployment running; set
//	                        TESTCONTAINERS_RYUK_DISABLED=true too, or the reaper
//	                        removes the deployment when the run exits
//	NB_E2E_ARTIFACTS_DIR    on failure, write the cluster and server logs here
//
// The harness reads NB_E2E_COMBINED_IMAGE, NB_E2E_CLIENT_IMAGE and
// NB_E2E_BUILDX_CACHE on top of these.
package e2e

import (
	"context"
	"log"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	env, err := bootstrap(ctx)
	cancel()
	if env != nil {
		defer env.teardown()
	}
	if err != nil {
		log.Printf("e2e: %v", err)
		if env != nil {
			env.logDiagnostics()
			env.collectArtifacts()
		}
		return 1
	}

	testEnv = env
	code := m.Run()
	if code != 0 {
		env.collectArtifacts()
	}
	return code
}

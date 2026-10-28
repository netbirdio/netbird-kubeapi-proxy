// SPDX-License-Identifier: AGPL-3.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kind/pkg/cluster"

	"github.com/netbirdio/netbird/e2e/harness"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	// managementURL is how everything in the cluster reaches management: the
	// harness's exposed address. It resolves only on the deployment's Docker
	// network, which is why the Kind nodes are created on that network.
	managementURL = "http://netbird.local:8080"

	kindClusterName = "netbird-kubeapi-proxy-e2e"

	// The node image has to match the Kind version in go.mod, which is why these
	// images carry it in their tag.
	defaultKindNodeImage = "ghcr.io/spegel-org/test-images/kind-node:v0.32.0-v1.37.0"

	// Kind reads the network to create nodes on from this variable, and only
	// from this variable.
	kindNetworkEnv = "KIND_EXPERIMENTAL_DOCKER_NETWORK"

	envProxyImage    = "IMG_REF"
	envKindNodeImage = "NB_E2E_KIND_NODE_IMAGE"
	envKeep          = "NB_E2E_KEEP"
	envArtifactsDir  = "NB_E2E_ARTIFACTS_DIR"

	// Building the server and client images from source dominates a cold run.
	bootstrapTimeout = 40 * time.Minute
)

// testEnv is the deployment and cluster TestMain brought up. Tests reach it
// through requireEnv.
var testEnv *environment

// environment is a running NetBird deployment and a Kind cluster attached to its
// network, with the proxy under test installed and two peers outside the cluster
// to reach it from.
type environment struct {
	srv *harness.Combined
	// nb is the management API as the account owner.
	nb *netbird.Client
	// clientImage is the NetBird client the outside peers run, built from the
	// pinned NetBird revision. Its shell and wget also serve the in-cluster
	// checks.
	clientImage string

	kind       *cluster.Provider
	kubeconfig string
	clientset  kubernetes.Interface

	workDir string

	// proxyPeer is the proxy as management lists it, once it has connected.
	proxyPeer api.Peer
	// reader is in readerGroup, which examples/read-only.yaml grants read
	// access to the cluster. outsider is in no group of its own.
	reader   *outsidePeer
	outsider *outsidePeer
}

// bootstrap brings the environment up. On error it returns whatever it got as
// far as, so the caller can still collect logs and tear it down.
func bootstrap(ctx context.Context) (*environment, error) {
	proxyImage := os.Getenv(envProxyImage)
	if proxyImage == "" {
		return nil, fmt.Errorf("%s must name the proxy image under test; make test-e2e builds it and sets it", envProxyImage)
	}
	workDir, err := os.MkdirTemp("", "netbird-kubeapi-proxy-e2e-*")
	if err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}
	env := &environment{workDir: workDir}

	log.Print("e2e: starting the NetBird deployment")
	env.srv, err = harness.StartCombined(ctx)
	if err != nil {
		return env, fmt.Errorf("start the NetBird deployment: %w", err)
	}
	pat, err := env.srv.Bootstrap(ctx)
	if err != nil {
		return env, fmt.Errorf("activate the account through /api/setup: %w", err)
	}
	env.nb = netbird.New(env.srv.BaseURL, pat)

	log.Print("e2e: building the NetBird client image")
	env.clientImage, err = harness.ClientImage(ctx)
	if err != nil {
		return env, fmt.Errorf("build the NetBird client image: %w", err)
	}

	log.Print("e2e: creating the Kind cluster")
	if err := env.createCluster(); err != nil {
		return env, err
	}
	if err := env.loadImages(ctx, proxyImage, env.clientImage); err != nil {
		return env, err
	}
	if err := env.checkManagementReachable(ctx); err != nil {
		return env, err
	}

	log.Print("e2e: installing the proxy")
	if err := env.installProxy(ctx, proxyImage, pat); err != nil {
		return env, err
	}

	log.Print("e2e: starting the peers outside the cluster")
	if err := env.startOutsidePeers(ctx); err != nil {
		return env, err
	}
	return env, nil
}

// createCluster creates the Kind cluster on the deployment's Docker network.
func (e *environment) createCluster() error {
	nodeImage := os.Getenv(envKindNodeImage)
	if nodeImage == "" {
		nodeImage = defaultKindNodeImage
	}
	e.kubeconfig = filepath.Join(e.workDir, "kubeconfig")
	e.kind = cluster.NewProvider()

	// A cluster left behind by an interrupted run holds the name, and its nodes
	// are attached to a network that no longer exists.
	if err := e.kind.Delete(kindClusterName, e.kubeconfig); err != nil {
		return fmt.Errorf("delete a leftover Kind cluster: %w", err)
	}

	prev, hadPrev := os.LookupEnv(kindNetworkEnv)
	if err := os.Setenv(kindNetworkEnv, e.srv.NetworkName()); err != nil {
		return err
	}
	err := e.kind.Create(kindClusterName,
		cluster.CreateWithNodeImage(nodeImage),
		cluster.CreateWithKubeconfigPath(e.kubeconfig),
		cluster.CreateWithWaitForReady(3*time.Minute),
		cluster.CreateWithDisplayUsage(false),
		cluster.CreateWithDisplaySalutation(false),
	)
	if hadPrev {
		_ = os.Setenv(kindNetworkEnv, prev)
	} else {
		_ = os.Unsetenv(kindNetworkEnv)
	}
	if err != nil {
		return fmt.Errorf("create Kind cluster from %s: %w", nodeImage, err)
	}

	cfg, err := clientcmd.BuildConfigFromFlags("", e.kubeconfig)
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	e.clientset, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create Kubernetes clientset: %w", err)
	}
	return nil
}

// checkManagementReachable runs a pod that fetches the management API from
// inside the cluster. The proxy depends on this path, and without the check its
// absence shows up much later as a proxy that never connects, with nothing
// pointing at DNS or the network.
func (e *environment) checkManagementReachable(ctx context.Context) error {
	script := fmt.Sprintf("wget -q -O /dev/null -T 5 %s/api/instance", managementURL)
	if err := e.runCheck(ctx, metav1.NamespaceDefault, "management-reachable", script); err != nil {
		return fmt.Errorf("pods in the cluster cannot reach management at %s: %w", managementURL, err)
	}
	return nil
}

// runCheck runs a shell command in a pod, from the client image, until it
// succeeds or about two minutes pass, and returns the pod's log if it never
// does.
func (e *environment) runCheck(ctx context.Context, namespace, name, script string) error {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:  "check",
					Image: e.clientImage,
					// Loaded into the nodes rather than pulled, like the proxy image.
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"sh", "-c", fmt.Sprintf("for i in $(seq 40); do %s && exit 0; sleep 3; done; exit 1", script)},
				},
			},
		},
	}
	pods := e.clientset.CoreV1().Pods(namespace)
	// A namespace's default service account appears a moment after the
	// namespace, and admission refuses the pod until it does.
	var createErr error
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
		_, createErr = pods.Create(ctx, pod, metav1.CreateOptions{})
		return createErr == nil, nil
	})
	if err != nil {
		return fmt.Errorf("create pod %s: %w (%w)", name, err, createErr)
	}
	defer func() {
		_ = pods.Delete(context.Background(), name, metav1.DeleteOptions{})
	}()

	var phase corev1.PodPhase
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 4*time.Minute, true, func(ctx context.Context) (bool, error) {
		got, err := pods.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		phase = got.Status.Phase
		return phase == corev1.PodSucceeded || phase == corev1.PodFailed, nil
	})
	if err == nil && phase == corev1.PodSucceeded {
		return nil
	}
	return fmt.Errorf("%q never succeeded in pod %s (phase %q, %v); log:\n%s",
		script, name, phase, err, e.podLogTail(context.Background(), namespace, name, "check", 20))
}

// teardown removes the cluster before the deployment: the Kind nodes sit on the
// deployment's network, which cannot be removed while they are attached.
func (e *environment) teardown() {
	if envBool(envKeep) {
		log.Printf("e2e: %s is set, leaving the environment running; kubeconfig: %s, management: %s",
			envKeep, e.kubeconfig, e.srvURL())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if e.kind != nil {
		if err := e.kind.Delete(kindClusterName, e.kubeconfig); err != nil {
			log.Printf("e2e: delete the Kind cluster: %v", err)
		}
	}
	for _, peer := range []*outsidePeer{e.reader, e.outsider} {
		if peer == nil {
			continue
		}
		if err := peer.client.Terminate(ctx); err != nil {
			log.Printf("e2e: terminate the %s peer: %v", peer.client.Hostname(), err)
		}
	}
	if e.srv != nil {
		if err := e.srv.Terminate(ctx); err != nil {
			log.Printf("e2e: terminate the NetBird deployment: %v", err)
		}
	}
	if err := os.RemoveAll(e.workDir); err != nil {
		log.Printf("e2e: remove %s: %v", e.workDir, err)
	}
}

// collectArtifacts writes the cluster's and the server's logs for CI to keep,
// when NB_E2E_ARTIFACTS_DIR asks for them. The environment is torn down before
// the run reports, so this is the only chance to read them.
func (e *environment) collectArtifacts() {
	dir := os.Getenv(envArtifactsDir)
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("e2e: create %s: %v", dir, err)
		return
	}
	if e.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := os.WriteFile(filepath.Join(dir, "netbird-server.log"), []byte(e.srv.Logs(ctx)), 0o644); err != nil {
			log.Printf("e2e: write the server log: %v", err)
		}
	}
	if e.kind != nil {
		if err := e.kind.CollectLogs(kindClusterName, filepath.Join(dir, "kind")); err != nil {
			log.Printf("e2e: collect the Kind logs: %v", err)
		}
	}
}

func (e *environment) srvURL() string {
	if e.srv == nil {
		return ""
	}
	return e.srv.BaseURL
}

// envBool reads a boolean knob. An unparsable value is reported rather than
// silently read as false.
func envBool(name string) bool {
	val := os.Getenv(name)
	if val == "" {
		return false
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		log.Printf("e2e: ignoring %s=%q: %v", name, val, err)
		return false
	}
	return b
}

// SPDX-License-Identifier: AGPL-3.0

//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	// proxyNamespace is where the proxy runs: manifests/rbac.yaml binds its
	// service account in the default namespace.
	proxyNamespace = metav1.NamespaceDefault
	// proxyName names the proxy's Deployment, service account and Secret in
	// manifests/.
	proxyName = "netbird-kubeapi-proxy"
	// proxyContainer is the proxy's container in manifests/deployment.yaml.
	proxyContainer = "proxy"
	// clusterName is the --cluster-name manifests/deployment.yaml passes, which
	// the proxy turns into its peer's DNS label.
	clusterName = "kubernetes"
	// dnsLabelSuffix is the label suffix the proxy appends to the cluster name,
	// cmd.KubernetesDNSSuffix in the NetBird client.
	dnsLabelSuffix = "netbird-kubeapi-proxy"
)

// manifestFiles are installed as they ship, apart from the image and the
// management URL, so the suite tests what users apply. read-only.yaml grants
// readerGroup read access.
var manifestFiles = []string{
	"manifests/rbac.yaml",
	"manifests/deployment.yaml",
	"examples/read-only.yaml",
}

// installProxy installs the proxy from this repository's manifests with a fresh
// setup key and the owner's token, and waits until management lists its peer as
// connected.
func (e *environment) installProxy(ctx context.Context, image, apiKey string) error {
	key, err := e.nb.SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-" + proxyName,
		Type:       "reusable",
		ExpiresIn:  int((24 * time.Hour).Seconds()),
		AutoGroups: []string{},
		// The proxy registers the cluster's DNS label, and management refuses
		// a peer whose key does not allow one.
		AllowExtraDnsLabels: new(true),
	})
	if err != nil {
		return fmt.Errorf("create the proxy's setup key: %w", err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: proxyName, Namespace: proxyNamespace},
		StringData: map[string]string{
			"setup-key": key.Key,
			"api-key":   apiKey,
		},
	}
	if _, err := e.clientset.CoreV1().Secrets(proxyNamespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create the proxy's Secret: %w", err)
	}

	objs, err := readManifests(manifestFiles...)
	if err != nil {
		return err
	}
	for _, obj := range objs {
		if deploy, ok := obj.(*appsv1.Deployment); ok {
			if err := pointAtDeployment(deploy, image); err != nil {
				return err
			}
		}
		if err := e.create(ctx, obj); err != nil {
			return err
		}
	}

	if err := e.waitProxyAvailable(ctx); err != nil {
		return err
	}
	e.proxyPeer, err = e.waitProxyPeer(ctx)
	return err
}

// pointAtDeployment runs the image under test and connects it to the harness's
// management instead of the cloud default.
func pointAtDeployment(deploy *appsv1.Deployment, image string) error {
	for i := range deploy.Spec.Template.Spec.Containers {
		c := &deploy.Spec.Template.Spec.Containers[i]
		if c.Name != proxyContainer {
			continue
		}
		c.Image = image
		// The image is loaded into the nodes, not pushed, and a :latest tag
		// would otherwise default to Always and try a registry pull.
		c.ImagePullPolicy = corev1.PullIfNotPresent
		c.Args = append(c.Args, "--management-url="+managementURL)
		return nil
	}
	return fmt.Errorf("deployment %s has no %s container", deploy.Name, proxyContainer)
}

// readManifests decodes every document in the given files, relative to the
// repository root.
func readManifests(files ...string) ([]runtime.Object, error) {
	decoder := scheme.Codecs.UniversalDeserializer()
	var objs []runtime.Object
	for _, file := range files {
		raw, err := os.ReadFile(filepath.Join("..", "..", file))
		if err != nil {
			return nil, err
		}
		reader := yaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
		for {
			doc, err := reader.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", file, err)
			}
			if len(bytes.TrimSpace(doc)) == 0 {
				continue
			}
			obj, _, err := decoder.Decode(doc, nil, nil)
			if err != nil {
				return nil, fmt.Errorf("decode %s: %w", file, err)
			}
			objs = append(objs, obj)
		}
	}
	return objs, nil
}

// create creates one of the kinds the manifests hold.
func (e *environment) create(ctx context.Context, obj runtime.Object) error {
	opts := metav1.CreateOptions{}
	var err error
	switch o := obj.(type) {
	case *corev1.ServiceAccount:
		_, err = e.clientset.CoreV1().ServiceAccounts(proxyNamespace).Create(ctx, o, opts)
	case *appsv1.Deployment:
		_, err = e.clientset.AppsV1().Deployments(proxyNamespace).Create(ctx, o, opts)
	case *rbacv1.ClusterRole:
		_, err = e.clientset.RbacV1().ClusterRoles().Create(ctx, o, opts)
	case *rbacv1.ClusterRoleBinding:
		_, err = e.clientset.RbacV1().ClusterRoleBindings().Create(ctx, o, opts)
	default:
		return fmt.Errorf("the suite does not install %T; add it to create", obj)
	}
	if err != nil {
		return fmt.Errorf("create %T: %w", obj, err)
	}
	return nil
}

// waitProxyAvailable waits for the proxy's Deployment to report an available
// replica.
func (e *environment) waitProxyAvailable(ctx context.Context) error {
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		deploy, err := e.clientset.AppsV1().Deployments(proxyNamespace).Get(ctx, proxyName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return deploy.Status.AvailableReplicas > 0, nil
	})
	if err != nil {
		return fmt.Errorf("the proxy Deployment never became available: %w", err)
	}
	return nil
}

// waitProxyPeer returns the proxy's peer once management lists it as connected.
// The proxy is the only peer that carries the cluster's DNS label.
func (e *environment) waitProxyPeer(ctx context.Context) (api.Peer, error) {
	var found api.Peer
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		peers, err := e.nb.Peers.List(ctx)
		if err != nil {
			return false, err
		}
		for _, peer := range peers {
			if isProxyPeer(peer) && peer.Connected {
				found = peer
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return api.Peer{}, fmt.Errorf("the proxy never connected to management as a peer labelled %s.%s: %w", clusterName, dnsLabelSuffix, err)
	}
	return found, nil
}

func isProxyPeer(peer api.Peer) bool {
	for _, label := range peer.ExtraDnsLabels {
		if strings.HasPrefix(label, clusterName+"."+dnsLabelSuffix) {
			return true
		}
	}
	return false
}

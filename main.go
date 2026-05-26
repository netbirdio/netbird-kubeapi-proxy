// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/netbirdio/netbird/client/embed"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"

	"github.com/netbirdio/netbird-kubeapi-proxy/internal/proxy"
)

func main() {
	var (
		mgmtURL       string
		apiKey        string
		setupKey      string
		kubeAPIServer string
		instanceName  string
		clusterName   string
	)
	flag.StringVar(&mgmtURL, "management-url", "https://api.netbird.io", "NetBird management URL")
	flag.StringVar(&apiKey, "api-key", os.Getenv("NB_API_KEY"), "NetBird API key")
	flag.StringVar(&setupKey, "setup-key", os.Getenv("NB_SETUP_KEY"), "NetBird setup key")
	flag.StringVar(&kubeAPIServer, "kubernetes-api-server", "https://kubernetes.default.svc.cluster.local", "Target Kubernetes API server URL")
	flag.StringVar(&instanceName, "instance-name", "", "Name of the instance")
	flag.StringVar(&clusterName, "cluster-name", "", "Name of the cluster")
	flag.Parse()

	err := run(context.Background(), kubeAPIServer, mgmtURL, apiKey, setupKey, instanceName, clusterName)
	if err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, kubeAPIServer, mgmtURL, apiKey, setupKey, instanceName, clusterName string) error {
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer cancel()
	g, gCtx := errgroup.WithContext(ctx)

	kubeAPIServerURL, err := url.Parse(kubeAPIServer)
	if err != nil {
		return err
	}
	if kubeAPIServerURL.Scheme != "https" || kubeAPIServerURL.Host == "" {
		return errors.New("kubernetes-api-server must be an absolute https URL")
	}

	netbirdClient := netbird.NewWithOptions(
		netbird.WithManagementURL(mgmtURL),
		netbird.WithBearerToken(apiKey),
	)

	opts := embed.Options{
		ManagementURL: mgmtURL,
		SetupKey:      setupKey,
		DeviceName:    instanceName,
		LogOutput:     io.Discard,
		DNSLabels:     []string{clusterName + "." + "netbird-kubeapi-proxy"},
	}
	embedClient, err := embed.New(opts)
	if err != nil {
		return err
	}
	err = embedClient.Start(ctx)
	if err != nil {
		return err
	}
	g.Go(func() error {
		<-gCtx.Done()
		return embedClient.Stop(context.Background())
	})

	proxySrv, err := proxy.Server(embedClient, netbirdClient, kubeAPIServerURL)
	if err != nil {
		return err
	}
	listener, err := embedClient.ListenTCP(":443")
	if err != nil {
		return err
	}
	g.Go(func() error {
		err := proxySrv.ServeTLS(listener, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-gCtx.Done()
		return proxySrv.Shutdown(context.Background())
	})

	err = g.Wait()
	if err != nil {
		return err
	}
	return nil
}

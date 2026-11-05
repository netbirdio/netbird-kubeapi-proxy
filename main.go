// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/cmd"
	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/shared/management/client"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"

	"github.com/netbirdio/netbird-kubeapi-proxy/internal/proxy"
	"github.com/netbirdio/netbird-kubeapi-proxy/internal/version"
)

func main() {
	var (
		mgmtURL       string
		apiKey        string
		setupKey      string
		kubeAPIServer string
		instanceName  string
		clusterName   string
		probeAddr     string
	)
	flag.StringVar(&mgmtURL, "management-url", "https://api.netbird.io", "NetBird management URL")
	flag.StringVar(&apiKey, "api-key", "", "NetBird API key")
	flag.StringVar(&setupKey, "setup-key", "", "NetBird setup key")
	flag.StringVar(&kubeAPIServer, "kubernetes-api-server", "https://kubernetes.default.svc.cluster.local/", "Target Kubernetes API server URL")
	flag.StringVar(&instanceName, "instance-name", "", "Name of the instance")
	flag.StringVar(&clusterName, "cluster-name", "", "Name of the cluster")
	flag.StringVar(&probeAddr, "probe-addr", ":8081", "Address probe server listens to")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	}))
	slog.SetDefault(logger)

	err := run(context.Background(), kubeAPIServer, mgmtURL, apiKey, setupKey, instanceName, clusterName, probeAddr)
	if err != nil {
		slog.Default().Error("exit due to error", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, kubeAPIServer, mgmtURL, apiKey, setupKey, instanceName, clusterName, probeAddr string) error {
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

	netbirdClient := newManagementClient(mgmtURL, apiKey)

	opts := embed.Options{
		ManagementURL: mgmtURL,
		SetupKey:      setupKey,
		DeviceName:    instanceName,
		LogOutput:     io.Discard,
		DNSLabels:     []string{clusterName + "." + cmd.KubernetesDNSSuffix},
	}
	embedClient, err := embed.New(opts)
	if err != nil {
		return err
	}
	err = embedClient.Start(ctx)
	if err != nil {
		// Start can fail after login has already registered the peer.
		deregisterPeerBestEffort(embedClient)
		return err
	}
	g.Go(func() error {
		<-gCtx.Done()
		deregisterPeerBestEffort(embedClient)
		return embedClient.Stop(context.Background())
	})

	peerStore := proxy.NewPeerStore(netbirdClient.Peers)
	proxySrv, err := proxy.Server(embedClient, peerStore, kubeAPIServerURL)
	if err != nil {
		cancel()
		_ = g.Wait()
		return err
	}
	listener, err := embedClient.ListenTCP(":443")
	if err != nil {
		cancel()
		_ = g.Wait()
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

	probeMux := http.NewServeMux()
	probeMux.HandleFunc("/readyz", func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	probeSrv := http.Server{
		Addr:    probeAddr,
		Handler: probeMux,
	}
	g.Go(func() error {
		err := probeSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-gCtx.Done()
		return probeSrv.Shutdown(context.Background())
	})

	slog.Default().Info("running API server proxy")
	err = g.Wait()
	if err != nil {
		return err
	}
	return nil
}

func newManagementClient(mgmtURL, apiKey string) *netbird.Client {
	return netbird.NewWithOptions(
		netbird.WithManagementURL(mgmtURL),
		netbird.WithBearerToken(apiKey),
		netbird.WithUserAgent(version.UserAgent()),
	)
}

// deregisterPeerBestEffort deregisters the peer within 5 seconds and only logs a
// failure, since Management's ephemeral cleanup removes the peer later anyway.
func deregisterPeerBestEffort(embedClient *embed.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := deregisterPeer(ctx, embedClient); err != nil {
		slog.Default().Warn("peer deregistration failed, falling back to management ephemeral cleanup", "error", err)
		return
	}
	slog.Default().Info("deregistered peer from management")
}

// deregisterPeer deletes this peer from Management with the peer-authenticated
// Logout RPC, so it disappears at once instead of lingering until Management's
// ephemeral cleanup. It authenticates with the peer's own WireGuard key, so no
// API key is needed.
func deregisterPeer(ctx context.Context, embedClient *embed.Client) error {
	cfg, err := embedClient.GetConfig()
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}
	if cfg.ManagementURL == nil {
		return errors.New("no management URL in config")
	}
	key, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	mgmClient, err := client.NewClient(ctx, cfg.ManagementURL.Host, key, cfg.ManagementURL.Scheme == "https")
	if err != nil {
		return fmt.Errorf("connect to management: %w", err)
	}
	defer func() { _ = mgmClient.Close() }()
	return mgmClient.Logout()
}

// SPDX-License-Identifier: AGPL-3.0

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/proxy"

	"github.com/netbirdio/netbird/client/embed"
)

const (
	AcceptHeader         = "Accept"
	AcceptEncodingHeader = "Accept-Encoding"
	ContentLengthHeader  = "Content-Length"
	ContentTypeHeader    = "Content-Type"
	UserAgentHeader      = "User-Agent"
	AuthorizationHeader  = "Authorization"
	RefererHeader        = "Referer"

	ConnectionHeader             = "Connection"
	UpgradeHeader                = "Upgrade"
	SecWebsocketKeyHeader        = "Sec-Websocket-Key"
	SecWebsocketVersionHeader    = "Sec-Websocket-Version"
	SecWebsocketProtocolHeader   = "Sec-Websocket-Protocol"
	SecWebsocketExtensionsHeader = "Sec-Websocket-Extensions"

	KubectlCommandHeader    = "Kubectl-Command"
	KubectlSessionHeader    = "Kubectl-Session"
	KubectlFlagsHeader      = "Kubectl-Flags"
	KubectlDeprecatedHeader = "Kubectl-Deprecated"
	KubectlBuildHeader      = "Kubectl-Build"
	ImpersonateUserHeader   = "Impersonate-User"
	ImpersonateGroupHeader  = "Impersonate-Group"
)

func Server(embedClient *embed.Client, peerStore *PeerStore, kubeAPIServerURL *url.URL) (*http.Server, error) {
	bearerToken, err := getBearerToken()
	if err != nil {
		return nil, err
	}
	certPool, err := getCertPool()
	if err != nil {
		return nil, err
	}
	handler := proxyHandler(peerStore, kubeAPIServerURL, certPool, bearerToken)

	stat, err := embedClient.Status()
	if err != nil {
		return nil, err
	}
	proxyCert, err := generateSelfSignedCert(stat.LocalPeerState.FQDN)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
	})
	mux.Handle("/api/", handler)
	mux.Handle("/apis/", handler)
	mux.Handle("/version/", handler)
	mux.Handle("/openapi/", handler)

	srv := http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{proxyCert},
			MinVersion:   tls.VersionTLS12,
		},
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return &srv, nil
}

type ErrorResponder struct{}

func (e *ErrorResponder) Error(w http.ResponseWriter, req *http.Request, err error) {
	slog.Default().Error("proxy request failed", "error", err)
}

func proxyHandler(peerStore *PeerStore, kubeAPIServerURL *url.URL, certPool *x509.CertPool, bearerToken string) http.HandlerFunc {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}

	upgradeHandler := proxy.NewUpgradeAwareHandler(kubeAPIServerURL, transport, true, false, &ErrorResponder{})
	upgradeHandler.UseRequestLocation = true

	return func(rw http.ResponseWriter, req *http.Request) {
		req = req.Clone(req.Context())

		// Remove dummy token as it has to be set to disable password prompting client side.
		if v := req.Header.Get("Authorization"); v == "Bearer none" {
			req.Header.Del("Authorization")
		}

		allowedHeaders := map[string]any{
			AcceptHeader:         nil,
			AcceptEncodingHeader: nil,
			ContentLengthHeader:  nil,
			ContentTypeHeader:    nil,
			UserAgentHeader:      nil,
			RefererHeader:        nil,

			KubectlCommandHeader:    nil,
			KubectlSessionHeader:    nil,
			KubectlFlagsHeader:      nil,
			KubectlDeprecatedHeader: nil,
			KubectlBuildHeader:      nil,

			ConnectionHeader:             nil,
			UpgradeHeader:                nil,
			SecWebsocketKeyHeader:        nil,
			SecWebsocketVersionHeader:    nil,
			SecWebsocketProtocolHeader:   nil,
			SecWebsocketExtensionsHeader: nil,
		}
		for k, v := range req.Header {
			if _, ok := allowedHeaders[k]; !ok {
				slog.Default().Warn("removing forbidden header", "key", k, "value", v)
				req.Header.Del(k)
			}
		}

		remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		getCtx, getCancel := context.WithTimeout(req.Context(), 10*time.Second)
		defer getCancel()
		peer, err := peerStore.Get(getCtx, remoteIP)
		if errors.Is(err, ErrNotFound) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		req.Header.Set(ImpersonateUserHeader, peer.UserId)
		for _, group := range peer.Groups {
			req.Header.Add(ImpersonateGroupHeader, group.Name)
		}
		req.Header.Set(AuthorizationHeader, "Bearer "+bearerToken)

		upgradeHandler.ServeHTTP(rw, req)
	}
}

func getBearerToken() (string, error) {
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("token cannot be empty")
	}
	return string(b), nil
}

func getCertPool() (*x509.CertPool, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	k8sCA, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	if ok := certPool.AppendCertsFromPEM(k8sCA); !ok {
		return nil, fmt.Errorf("failed to append Kubernetes CA certificate")
	}
	return certPool, nil
}

func generateSelfSignedCert(fqdn string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"NetBird K8s Auth Proxy"},
			CommonName:   fqdn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{fqdn},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

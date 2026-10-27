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
	"github.com/netbirdio/netbird/shared/management/http/api"
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
	StreamProtocolVersionHeader  = "X-Stream-Protocol-Version"

	KubectlCommandHeader    = "Kubectl-Command"
	KubectlSessionHeader    = "Kubectl-Session"
	KubectlFlagsHeader      = "Kubectl-Flags"
	KubectlDeprecatedHeader = "Kubectl-Deprecated"
	KubectlBuildHeader      = "Kubectl-Build"
	ImpersonateUserHeader   = "Impersonate-User"
	ImpersonateGroupHeader  = "Impersonate-Group"

	PeerUserPrefix = "netbird:peer:"
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

	srv := http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{proxyCert},
			MinVersion:   tls.VersionTLS12,
		},
		Handler:           newMux(handler),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return &srv, nil
}

// proxiedPrefixes are the API server path prefixes exposed through the proxy.
var proxiedPrefixes = []string{"/api", "/apis", "/version", "/openapi"}

func newMux(handler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
	})
	for _, prefix := range proxiedPrefixes {
		// Register the exact path as well as the subtree. With only the
		// subtree pattern ("/api/") registered, ServeMux answers a request
		// for the bare path ("/api") with a redirect to the trailing-slash
		// form instead of dispatching it to the handler. Discovery clients
		// request exactly /api, /apis and /version, and not all of them
		// follow redirects (client-go does, kube-rs does not), so the
		// redirect surfaces as a failed API discovery for those clients.
		mux.Handle(prefix, handler)
		mux.Handle(prefix+"/", handler)
	}
	return mux
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

	// UpgradeAwareHandler 301-redirects any GET or HEAD request to its
	// trailing-slash form when Location.Path is empty, as a workaround for
	// https://issue.k8s.io/4958. This breaks exact-path API endpoints such
	// as /openapi/v2, whose trailing-slash variants the API server does not
	// serve. Ensure the location always has a non-empty path.
	location := *kubeAPIServerURL
	if location.Path == "" {
		location.Path = "/"
	}

	upgradeHandler := proxy.NewUpgradeAwareHandler(&location, transport, true, false, &ErrorResponder{})
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
			StreamProtocolVersionHeader:  nil,
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
		req.Header.Set(ImpersonateUserHeader, impersonateUser(peer))
		for _, group := range peer.Groups {
			req.Header.Add(ImpersonateGroupHeader, group.Name)
		}
		req.Header.Set(AuthorizationHeader, "Bearer "+bearerToken)

		upgradeHandler.ServeHTTP(rw, req)
	}
}

func impersonateUser(peer api.Peer) string {
	if peer.UserId != "" {
		return peer.UserId
	}
	return PeerUserPrefix + peer.Id
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

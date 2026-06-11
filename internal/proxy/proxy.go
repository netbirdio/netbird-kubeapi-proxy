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
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	AcceptHeader           = "Accept"
	AcceptEncodingHeader   = "Accept-Encoding"
	ContentLengthHeader    = "Content-Length"
	ContentTypeHeader      = "Content-Type"
	UserAgentHeader        = "User-Agent"
	AuthorizationHeader    = "Authorization"
	ImpersonateUserHeader  = "Impersonate-User"
	ImpersonateGroupHeader = "Impersonate-Group"

	ConnectionHeader             = "Connection"
	UpgradeHeader                = "Upgrade"
	SecWebsocketKeyHeader        = "Sec-Websocket-Key"
	SecWebsocketVersionHeader    = "Sec-Websocket-Version"
	SecWebsocketProtocolHeader   = "Sec-Websocket-Protocol"
	SecWebsocketExtensionsHeader = "Sec-Websocket-Extensions"
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
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return &srv, nil
}

func proxyHandler(peerStore *PeerStore, kubeAPIServerURL *url.URL, certPool *x509.CertPool, bearerToken string) http.HandlerFunc {
	type peerCtxKey struct{}

	rewrite := func(pr *httputil.ProxyRequest) {
		allowedHeaders := map[string]any{
			AcceptHeader:         nil,
			AcceptEncodingHeader: nil,
			ContentLengthHeader:  nil,
			ContentTypeHeader:    nil,
			UserAgentHeader:      nil,
			// WebSocket negotiation headers for streaming subresources
			// (kubectl exec/attach/port-forward/cp). These are not
			// hop-by-hop, so httputil.ReverseProxy does not restore them;
			// they must survive the allowlist for the upstream API server to
			// complete the WebSocket handshake.
			SecWebsocketKeyHeader:        nil,
			SecWebsocketVersionHeader:    nil,
			SecWebsocketProtocolHeader:   nil,
			SecWebsocketExtensionsHeader: nil,
		}
		for k := range pr.Out.Header {
			if _, ok := allowedHeaders[k]; !ok {
				pr.Out.Header.Del(k)
			}
		}

		// Preserve the connection-upgrade handshake for streaming
		// subresources. The allowlist above strips the hop-by-hop
		// Connection/Upgrade headers; without them httputil.ReverseProxy
		// treats the request as non-upgrade and the API server rejects it
		// with "Upgrade request required" (breaking kubectl
		// exec/attach/port-forward/cp over both WebSocket and SPDY).
		// Reconstruct them from the inbound request rather than allowlisting
		// the client-supplied Connection header, so a client cannot name
		// proxy-set headers (Authorization, Impersonate-*) as hop-by-hop and
		// have them stripped before reaching the API server.
		if upgrade := pr.In.Header.Get(UpgradeHeader); upgrade != "" {
			pr.Out.Header.Set(ConnectionHeader, "Upgrade")
			pr.Out.Header.Set(UpgradeHeader, upgrade)
		}

		peer, ok := pr.In.Context().Value(peerCtxKey{}).(api.Peer)
		if !ok {
			return
		}
		pr.Out.Header.Set(ImpersonateUserHeader, peer.UserId)
		for _, group := range peer.Groups {
			pr.Out.Header.Add(ImpersonateGroupHeader, group.Name)
		}
		pr.Out.Header.Set(AuthorizationHeader, "Bearer "+bearerToken)
		pr.SetURL(kubeAPIServerURL)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite:   rewrite,
	}

	return func(rw http.ResponseWriter, req *http.Request) {
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
		peerCtx := context.WithValue(req.Context(), peerCtxKey{}, peer)
		proxy.ServeHTTP(rw, req.WithContext(peerCtx))
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

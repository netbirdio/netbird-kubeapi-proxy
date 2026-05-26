// SPDX-License-Identifier: BSD-3-Clause

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
)

func Server(embedClient *embed.Client, netbirdClient *netbird.Client, kubeAPIServerURL *url.URL) (*http.Server, error) {
	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}
	bearerToken := string(saToken)

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

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs: certPool,
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			allowedHeaders := map[string]any{
				"Accept":          nil,
				"Accept-Encoding": nil,
				"Content-Length":  nil,
				"Content-Type":    nil,
				"User-Agent":      nil,
			}
			for k := range pr.Out.Header {
				if _, ok := allowedHeaders[k]; !ok {
					pr.Out.Header.Del(k)
				}
			}

			remoteIP, _, err := net.SplitHostPort(pr.In.RemoteAddr)
			if err != nil {
				return
			}
			listCtx, listCancel := context.WithTimeout(pr.In.Context(), 10*time.Second)
			defer listCancel()
			peers, err := netbirdClient.Peers.List(listCtx, netbird.PeerIPFilter(remoteIP))
			if err != nil {
				return
			}
			if len(peers) != 1 {
				return
			}
			peer := peers[0]
			pr.Out.Header.Set("Impersonate-User", peer.UserId)
			for _, group := range peer.Groups {
				pr.Out.Header.Add("Impersonate-Group", group.Name)
			}

			pr.Out.Header.Set("Authorization", "Bearer "+bearerToken)
			pr.SetURL(kubeAPIServerURL)
		},
	}

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
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return &srv, nil
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

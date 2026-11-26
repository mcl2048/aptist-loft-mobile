package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type streamDialer interface {
	DialTCP(context.Context, string) (net.Conn, error)
}

type httpsTransfer struct {
	Bytes  int
	SHA256 string
}

func verifiedHTTPS(ctx context.Context, dialer streamDialer, target, hostname string, roots *x509.CertPool) (httpsTransfer, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	adapter := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{ServerName: hostname, RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialTCP(ctx, target)
	}}
	defer adapter.CloseIdleConnections()
	client := &http.Client{Transport: adapter, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+"/", nil)
	if err != nil {
		return httpsTransfer{}, stage("literal_request", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return httpsTransfer{}, stage("literal_https", err)
	}
	defer func() { _ = response.Body.Close() }() // Read errors/size are checked before a transfer receipt.
	if response.StatusCode != http.StatusOK {
		return httpsTransfer{}, stage("literal_status", io.ErrUnexpectedEOF)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return httpsTransfer{}, stage("literal_body", err)
	}
	defer clear(body)
	if len(body) == 0 || len(body) > 4096 {
		return httpsTransfer{}, stage("literal_body_limit", io.ErrUnexpectedEOF)
	}
	digest := sha256.Sum256(body)
	return httpsTransfer{Bytes: len(body), SHA256: fmt.Sprintf("%x", digest)}, nil
}

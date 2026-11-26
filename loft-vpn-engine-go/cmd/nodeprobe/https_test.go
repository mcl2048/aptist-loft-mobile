package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
)

type localStreamDialer struct{}

func (localStreamDialer) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target)
}

// Verify real TLS/Host and bounded response transfer, independently of the
// proxy authentication and Android/TUN layers tested elsewhere.
func TestVerifiedHTTPSRequiresTLSIdentityCompleteBodyAndNoRedirects(t *testing.T) {
	for _, test := range []struct {
		name, host, body string
		status           int
		wantSuccess      bool
	}{{"transfer", "node.test", "complete bounded transfer", http.StatusOK, true}, {"wrong_identity", "other.test", "complete bounded transfer", http.StatusOK, false}, {"oversized_body", "node.test", strings.Repeat("x", 4097), http.StatusOK, false}, {"redirect", "node.test", "redirected", http.StatusFound, false}, {"status_error", "node.test", "rejected", http.StatusForbidden, false}} {
		t.Run(test.name, func(t *testing.T) {
			identity := testsupport.Certificates(t)
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.Host != test.host {
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				if test.status == http.StatusFound {
					writer.Header().Set("Location", "https://other.test/redirect")
				}
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			server.TLS = identity.ServerTLS.Clone()
			server.TLS.ClientAuth = tls.NoClientCert
			server.TLS.ClientCAs = nil
			server.StartTLS()
			defer server.Close()
			transfer, err := verifiedHTTPS(context.Background(), localStreamDialer{}, server.Listener.Addr().String(), test.host, identity.ClientTLS.RootCAs)
			if (err == nil) != test.wantSuccess {
				t.Fatal("verified HTTPS accepted an invalid transfer or rejected a valid one")
			}
			if test.wantSuccess && (transfer.Bytes != len(test.body) || len(transfer.SHA256) != 64 || requests.Load() != 1) {
				t.Fatal("verified HTTPS did not complete one bounded actual response")
			}
			if test.status == http.StatusFound && requests.Load() != 1 {
				t.Fatal("diagnostic followed an unapproved redirect")
			}
		})
	}
}

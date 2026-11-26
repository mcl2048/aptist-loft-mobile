package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	transport "loft.local/hyrakenx"
)

func run() error {
	var input struct {
		Address string `json:"address"`
		Share   struct {
			Seed              string `json:"seed"`
			SNI               string `json:"sni"`
			Certificate       string `json:"certificate"`
			ClientCertificate string `json:"client_certificate"`
			ClientKey         string `json:"client_key"`
		} `json:"share"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	client, err := tls.X509KeyPair([]byte(input.Share.ClientCertificate), []byte(input.Share.ClientKey))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(input.Share.Certificate)) {
		return errors.New("invalid server certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	peer, err := transport.Dial(ctx, input.Address, &tls.Config{Certificates: []tls.Certificate{client}, RootCAs: pool, ServerName: input.Share.SNI}, []byte(input.Share.Seed), []transport.Suite{transport.SuiteRoccaS, transport.SuiteChaCha20Poly1305})
	if err != nil {
		return err
	}
	defer peer.Close()
	fmt.Println(peer.Suite())
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

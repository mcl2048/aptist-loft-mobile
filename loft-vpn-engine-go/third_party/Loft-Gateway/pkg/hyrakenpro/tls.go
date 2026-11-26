package hyrakenpro

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
)

func clientTLSConfig(cfg ClientConfig, u *url.URL) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS13}
	if cfg.TLSConfig != nil {
		config = cfg.TLSConfig.Clone()
	}
	if config.MinVersion < tls.VersionTLS13 {
		config.MinVersion = tls.VersionTLS13
	}
	config.MaxVersion = tls.VersionTLS13
	config.NextProtos = clientALPN(cfg.Transport)
	if config.ClientSessionCache == nil {
		config.ClientSessionCache = tls.NewLRUClientSessionCache(16)
	}
	if config.ServerName == "" {
		config.ServerName = u.Hostname()
	}
	if cfg.CertificatePin == "" {
		return config, nil
	}
	pin, err := base64.StdEncoding.Strict().DecodeString(cfg.CertificatePin)
	if err != nil || len(pin) != 32 {
		return nil, errors.New("hyrakenpro: invalid SPKI SHA256 pin")
	}
	previous := config.VerifyConnection
	name := config.ServerName
	config.InsecureSkipVerify = true // Exact pinned leaf is checked below, including name and validity.
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("hyrakenpro: missing TLS certificate")
		}
		leaf := state.PeerCertificates[0]
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
			return errors.New("hyrakenpro: TLS pin rejected")
		}
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if err != nil {
			return fmt.Errorf("hyrakenpro: pinned TLS identity rejected: %w", err)
		}
		if previous != nil {
			return previous(state)
		}
		return nil
	}
	return config, nil
}

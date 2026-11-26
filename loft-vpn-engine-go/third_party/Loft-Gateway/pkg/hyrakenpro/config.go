// Package hyrakenpro implements an independent hybrid-authenticated TLS 1.3
// multiplexed tunnel over raw TCP or bidirectional gRPC over HTTP/2.
package hyrakenpro

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"loft.local/hydra"
	"loft.local/trafficprofile"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	TransportAuto         = "auto"
	TransportTCP          = "tcp"
	TransportGRPC         = "grpc"
	SuiteAuto             = "auto"
	SuiteAES256GCM        = "aes-256-gcm"
	SuiteChaCha20Poly1305 = "chacha20-poly1305"
	SuiteAsconAEAD128     = "ascon-aead128"
	// SuiteRoccaS prefers Rocca-S and authenticates a ChaCha fallback capability.
	SuiteRoccaS  = "rocca-s"
	rawALPN      = "hyraken-pro/1"
	maxStreams   = 64
	maxSessions  = 8
	maxTarget    = 1024
	maxPacket    = 65507
	maxFrameData = 16384
)

// ClientConfig describes a verified TLS endpoint; URL must use https.
type ClientConfig struct {
	URL, Seed, Transport, Suite, Congestion string
	PacketEncoding                          string
	TLSConfig                               *tls.Config
	CertificatePin                          string
	DialContext                             func(context.Context, string, string) (net.Conn, error)
	Profile                                 *trafficprofile.Profile
	Connections                             int
	ElasticMux                              bool
	Hydra                                   *hydra.Config
	// HydraObserver is local, nonblocking and reports accepted shaped DATA/PAD.
	HydraObserver func(records, paddingBytes int)
	owner         context.Context
}

// ServerConfig never grants target-dialing authority; accepted streams belong to the router.
type ServerConfig struct {
	Seed, Path, Transport, Suite, Congestion string
	PacketEncoding                           string
	Profile                                  *trafficprofile.Profile
	Fallback                                 http.Handler
	Hydra                                    *hydra.Config
}

func validateSeed(s string) error {
	if len(s) < 32 || len(s) > 256 || strings.TrimSpace(s) != s {
		return errors.New("hyrakenpro: seed must contain 32..256 bytes")
	}
	return nil
}
func normalizeModes(transport, suite, congestion *string) error {
	if *transport == "" {
		*transport = TransportAuto
	}
	if *transport != TransportAuto && *transport != TransportTCP && *transport != TransportGRPC {
		return errors.New("hyrakenpro: invalid transport")
	}
	if *suite == "" {
		*suite = SuiteAuto
	}
	// Requested policy survives normalization. Availability is negotiated before
	// newCiphers; the raw Rocca factory still refuses unsupported AES-NI builds.
	switch *suite {
	case SuiteAuto, SuiteAES256GCM, SuiteChaCha20Poly1305, SuiteRoccaS, SuiteAsconAEAD128:
	default:
		return errors.New("hyrakenpro: invalid suite")
	}
	if *congestion == "" {
		*congestion = "beast"
	}
	if *congestion != "beast" && *congestion != "bbr" {
		return errors.New("hyrakenpro: invalid congestion")
	}
	return nil
}
func normalizeHydra(p *hydra.Config) (*hydra.Config, error) {
	if p == nil {
		return nil, nil
	}
	v, e := hydra.Normalize(*p)
	if e != nil {
		return nil, e
	}
	return &v, nil
}
func normalizePacketEncoding(s *string) error {
	if *s == "none" {
		*s = ""
	}
	if *s != "" && *s != "xudp" {
		return errors.New("hyrakenpro: unsupported packet encoding")
	}
	return nil
}
func validPath(s string) bool {
	return len(s) > 0 && len(s) <= 1024 && s[0] == '/' && !strings.ContainsAny(s, "?#\r\n\x00")
}
func normalizeClientConfig(c ClientConfig) (ClientConfig, *url.URL, error) {
	if e := normalizePacketEncoding(&c.PacketEncoding); e != nil {
		return c, nil, e
	}
	if e := validateSeed(c.Seed); e != nil {
		return c, nil, e
	}
	u, e := url.Parse(c.URL)
	if e != nil {
		return c, nil, e
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || !validPath(u.Path) {
		return c, nil, errors.New("hyrakenpro: absolute HTTPS endpoint with path required")
	}
	if e = normalizeModes(&c.Transport, &c.Suite, &c.Congestion); e != nil {
		return c, nil, e
	}
	if c.Connections < 0 || c.Connections > maxSessions {
		return c, nil, errors.New("hyrakenpro: connections must be 1..8")
	}
	if c.Connections == 0 {
		c.Connections = 4
	}
	if c.TLSConfig != nil {
		if c.TLSConfig.InsecureSkipVerify {
			return c, nil, errors.New("hyrakenpro: TLS verification required")
		}
		c.TLSConfig = c.TLSConfig.Clone()
		if c.TLSConfig.MaxVersion != 0 && c.TLSConfig.MaxVersion < tls.VersionTLS13 {
			return c, nil, errors.New("hyrakenpro: TLS 1.3 required")
		}
	}
	if c.TLSConfig == nil {
		c.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	}
	if c.TLSConfig.ClientSessionCache == nil {
		c.TLSConfig.ClientSessionCache = tls.NewLRUClientSessionCache(32)
	}
	if c.CertificatePin != "" {
		p, e := base64.StdEncoding.Strict().DecodeString(c.CertificatePin)
		if e != nil || len(p) != 32 {
			return c, nil, errors.New("hyrakenpro: invalid SPKI SHA256 pin")
		}
	}
	c.Profile, e = NormalizeChameleonProfile(c.Profile)
	if e != nil {
		return c, nil, e
	}
	c.Hydra, e = normalizeHydra(c.Hydra)
	return c, u, e
}
func normalizeServerConfig(c ServerConfig) (ServerConfig, error) {
	if e := normalizePacketEncoding(&c.PacketEncoding); e != nil {
		return c, e
	}
	if e := validateSeed(c.Seed); e != nil {
		return c, e
	}
	if !validPath(c.Path) {
		return c, errors.New("hyrakenpro: invalid path")
	}
	if e := normalizeModes(&c.Transport, &c.Suite, &c.Congestion); e != nil {
		return c, e
	}
	var e error
	c.Profile, e = NormalizeChameleonProfile(c.Profile)
	if e != nil {
		return c, e
	}
	c.Hydra, e = normalizeHydra(c.Hydra)
	return c, e
}
func clientALPN(transport string) []string {
	switch transport {
	case TransportTCP:
		return []string{rawALPN}
	case TransportGRPC:
		return []string{"h2"}
	default:
		return []string{"h2", rawALPN}
	}
}

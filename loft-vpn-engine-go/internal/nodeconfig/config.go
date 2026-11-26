// Package nodeconfig parses session-local adapter input without producing
// credential-bearing diagnostics or control snapshots.
package nodeconfig

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var errInvalidNode = errors.New("loft.vpn.invalid_node")
var errInvalidMaterial = errors.New("loft.vpn.invalid_tls_material")
var hostName = regexp.MustCompile(`(?i)\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z`)

// Config is private transport material. Every field is omitted from JSON.
type Config struct {
	Protocol                                                                string      `json:"-"`
	Address                                                                 string      `json:"-"`
	Username                                                                string      `json:"-"`
	Password                                                                string      `json:"-"`
	Seed                                                                    []byte      `json:"-"`
	TLS                                                                     *tls.Config `json:"-"`
	Pin, Path, Transport, Suite, Congestion, PacketEncoding, TrafficProfile string      `json:"-"`
	Mode, Scenario                                                          string      `json:"-"`
	RateMbps, Connections                                                   int         `json:"-"`
	ElasticMux                                                              bool        `json:"-"`
}

// Parse validates bounded input for the compiled adapters.
// It does no DNS/network work and never returns the URI in an error.
func Parse(raw string) (*Config, error) {
	if len(raw) == 0 || len(raw) > 524288 || !utf8.ValidString(raw) || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n") {
		return nil, errInvalidNode
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Path != "" || !validHost(u.Hostname()) {
		return nil, errInvalidNode
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "hyrakenx" && scheme != "hyraken-pro" && scheme != "socks5" && scheme != "socks" {
		return nil, errInvalidNode
	}
	port := u.Port()
	if port == "" {
		if scheme == "socks5" || scheme == "socks" {
			port = "1080"
		} else {
			return nil, errInvalidNode
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, errInvalidNode
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errInvalidNode
	}
	for _, values := range q {
		if len(values) != 1 {
			return nil, errInvalidNode
		}
	}
	c := &Config{Protocol: scheme, Address: net.JoinHostPort(strings.ToLower(u.Hostname()), strconv.Itoa(p))}
	if scheme == "socks" || scheme == "socks5" {
		if len(q) != 0 {
			return nil, errInvalidNode
		}
		c.Protocol = "socks5"
		if u.User != nil {
			c.Username = u.User.Username()
			c.Password, _ = u.User.Password()
			if len(c.Username) > 255 || len(c.Password) > 255 {
				return nil, errInvalidNode
			}
		}
		return c, nil
	}
	if u.User == nil {
		return nil, errInvalidNode
	}
	seed := u.User.Username()
	if _, hasPassword := u.User.Password(); hasPassword || len(seed) < 32 || len(seed) > 256 || strings.TrimSpace(seed) != seed || strings.ContainsAny(seed, "\x00\r\n") {
		return nil, errInvalidNode
	}
	c.Seed = []byte(seed)
	allowed := map[string]bool{"sni": true, "pin": true}
	if scheme == "hyrakenx" {
		for _, key := range []string{"server_cert", "ca", "cert", "key", "mode", "scenario", "rate"} {
			allowed[key] = true
		}
	} else {
		for _, key := range []string{"certificate", "path", "transport", "engine", "suite", "congestion", "connections", "traffic_profile", "elastic_mux", "isolation", "packet_encoding"} {
			allowed[key] = true
		}
	}
	for key := range q {
		if !allowed[key] {
			return nil, errInvalidNode
		}
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	if !validHost(sni) {
		return nil, errInvalidNode
	}
	c.Pin = q.Get("pin")
	if c.Pin == "" {
		return nil, errInvalidMaterial
	}
	certificateField := "certificate"
	if scheme == "hyrakenx" {
		certificateField = "server_cert"
	}
	serverPEM, err := decodeMaterial(q.Get(certificateField), 65536)
	if err != nil {
		return nil, err
	}
	serverCerts, err := certificates(serverPEM)
	if err != nil {
		return nil, err
	}
	pin, err := base64.StdEncoding.Strict().DecodeString(c.Pin)
	if err != nil || len(pin) != 32 {
		return nil, errInvalidMaterial
	}
	spki := sha256.Sum256(serverCerts[0].RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(spki[:], pin) != 1 || serverCerts[0].VerifyHostname(sni) != nil {
		return nil, errInvalidMaterial
	}
	if now := time.Now(); now.Before(serverCerts[0].NotBefore) || !now.Before(serverCerts[0].NotAfter) {
		return nil, errInvalidMaterial
	}
	roots := x509.NewCertPool()
	for _, certificate := range serverCerts {
		roots.AddCert(certificate)
	}
	c.TLS = &tls.Config{ServerName: sni, RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	if scheme == "hyrakenx" {
		caPEM, err := decodeMaterial(q.Get("ca"), 65536)
		if err != nil {
			return nil, err
		}
		cas, err := certificates(caPEM)
		if err != nil {
			return nil, err
		}
		clientPEM, err := decodeMaterial(q.Get("cert"), 16384)
		if err != nil {
			return nil, err
		}
		keyPEM, err := decodeMaterial(q.Get("key"), 16384)
		if err != nil {
			return nil, err
		}
		pair, err := tls.X509KeyPair(clientPEM, keyPEM)
		clear(keyPEM)
		if err != nil || len(pair.Certificate) == 0 {
			return nil, errInvalidMaterial
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, errInvalidMaterial
		}
		clientRoots := x509.NewCertPool()
		for _, ca := range cas {
			clientRoots.AddCert(ca)
		}
		intermediates := x509.NewCertPool()
		for _, der := range pair.Certificate[1:] {
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, errInvalidMaterial
			}
			intermediates.AddCert(certificate)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: clientRoots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return nil, errInvalidMaterial
		}
		c.TLS.Certificates = []tls.Certificate{pair}
		c.Mode = defaultValue(q.Get("mode"), "flash")
		c.Scenario = defaultValue(q.Get("scenario"), "bulk")
		if !oneOf(c.Mode, "flash", "beast") || !oneOf(c.Scenario, "bulk", "lossy", "speedtest") {
			return nil, errInvalidNode
		}
		if rate := q.Get("rate"); rate != "" {
			c.RateMbps, err = strconv.Atoi(rate)
			if err != nil || c.RateMbps < 0 || c.RateMbps > 20000 || (c.RateMbps != 0 && c.Mode != "beast") {
				return nil, errInvalidNode
			}
		}
		return c, nil
	}
	c.Path = defaultValue(q.Get("path"), "/hyraken.pro/Tunnel")
	if len(c.Path) > 1024 || c.Path[0] != '/' || strings.ContainsAny(c.Path, "?#\r\n\x00") {
		return nil, errInvalidNode
	}
	c.Transport = defaultValue(q.Get("transport"), "auto")
	c.Suite = defaultValue(q.Get("suite"), "auto")
	c.Congestion = defaultValue(q.Get("congestion"), "beast")
	c.TrafficProfile = defaultValue(q.Get("traffic_profile"), "auto")
	c.PacketEncoding = q.Get("packet_encoding")
	if c.PacketEncoding == "none" {
		c.PacketEncoding = ""
	}
	if !oneOf(c.Transport, "auto", "tcp", "grpc") || !oneOf(c.Suite, "auto", "aes-256-gcm", "chacha20-poly1305", "rocca-s", "ascon-aead128") || !oneOf(c.Congestion, "beast", "bbr") || !oneOf(c.TrafficProfile, "auto", "gaming", "streaming", "web_browsing", "wechat_voice") || !oneOf(c.PacketEncoding, "", "xudp") {
		return nil, errInvalidNode
	}
	if engine := q.Get("engine"); engine != "" && !oneOf(engine, "ghostx", "naive") {
		return nil, errInvalidNode
	}
	for _, key := range []string{"elastic_mux", "isolation"} {
		if value := q.Get(key); value != "" && !oneOf(value, "0", "1") {
			return nil, errInvalidNode
		}
	}
	if connections := q.Get("connections"); connections != "" {
		count, err := strconv.Atoi(connections)
		if err != nil || count < 1 || count > 8 {
			return nil, errInvalidNode
		}
	}
	c.Connections = 1
	c.ElasticMux = false
	return c, nil
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && ip.Zone() == ""
	}
	return hostName.MatchString(host)
}

func decodeMaterial(encoded string, max int) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > ((max+2)/3)*4 {
		return nil, errInvalidMaterial
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) > max {
		return nil, errInvalidMaterial
	}
	return data, nil
}

func certificates(data []byte) ([]*x509.Certificate, error) {
	var result []*x509.Certificate
	for len(strings.TrimSpace(string(data))) > 0 {
		block, remaining := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(result) >= 8 {
			return nil, errInvalidMaterial
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errInvalidMaterial
		}
		result = append(result, certificate)
		data = remaining
	}
	if len(result) == 0 {
		return nil, errInvalidMaterial
	}
	return result, nil
}

func defaultValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

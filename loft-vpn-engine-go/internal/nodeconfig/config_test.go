package nodeconfig

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
)

// Invalid or duplicate fields must fail before creating any socket, and errors
// must not copy an untrusted node URI into diagnostics.
func TestParseRejectsInvalidAndOversizedInputsWithRedactedErrors(t *testing.T) {
	for _, raw := range []string{"", "socks4://127.0.0.1:1080", "socks5://127.0.0.1:0", "socks5://user:private-synthetic-password@127.0.0.1:65536", "socks5://127.0.0.1:1080?unknown=1", "hyraken-pro://synthetic-seed@node.test:443?path=/x&path=/y", strings.Repeat("x", 524289)} {
		config, err := Parse(raw)
		if err == nil || config != nil {
			t.Fatal("invalid node was accepted")
		}
		if strings.Contains(err.Error(), "private-synthetic-password") || len(err.Error()) > 100 {
			t.Fatal("parser error copied private input")
		}
	}
}

// A parsed SOCKS endpoint must preserve percent-decoded authentication and the
// default port without putting secrets into serialized control descriptions.
func TestParseSocksKeepsCredentialsPrivateAndPreservesDefaultPort(t *testing.T) {
	config, err := Parse("socks5://test%40user:test%3Apassword@node.test#label")
	if err != nil {
		t.Fatalf("valid synthetic SOCKS node rejected: %v", err)
	}
	if config.Protocol != "socks5" || config.Address != "node.test:1080" || config.Username != "test@user" || config.Password != "test:password" {
		t.Fatal("SOCKS endpoint/authentication changed")
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "test@user") || strings.Contains(string(raw), "test:password") || strings.Contains(string(raw), "node.test") {
		t.Fatal("configuration serialization disclosed private fields")
	}
}

// X requires a matching client key and verified server identity/pin; preserving
// its URI options must not weaken TLS or accidentally use Pro's UDP framing.
func TestParseXVerifiesMaterialsAndPreservesSenderPolicy(t *testing.T) {
	id := testsupport.Certificates(t)
	q := url.Values{"sni": {"node.test"}, "pin": {id.Pin}, "server_cert": {base64.StdEncoding.EncodeToString(id.Server)}, "ca": {base64.StdEncoding.EncodeToString(id.CA)}, "cert": {base64.StdEncoding.EncodeToString(id.Client)}, "key": {base64.StdEncoding.EncodeToString(id.ClientKey)}, "mode": {"beast"}, "scenario": {"lossy"}, "rate": {"100"}}
	raw := "hyrakenx://0123456789abcdef0123456789abcdef@node.test:443?" + q.Encode()
	config, err := Parse(raw)
	if err != nil {
		t.Fatalf("valid synthetic X node rejected: %v", err)
	}
	if config.Protocol != "hyrakenx" || config.TLS.InsecureSkipVerify || len(config.TLS.Certificates) != 1 || config.TLS.ServerName != "node.test" || config.Mode != "beast" || config.Scenario != "lossy" || config.RateMbps != 100 {
		t.Fatal("X TLS or sender policy changed")
	}
	q.Set("pin", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if _, err := Parse("hyrakenx://0123456789abcdef0123456789abcdef@node.test:443?" + q.Encode()); err == nil {
		t.Fatal("mismatched X pin accepted")
	}
}

// Mobile has its own physical gate: valid imported pool hints must not cause
// Pro to warm four sessions or start the upstream elastic reaper.
func TestParseProRetainsWireOptionsAndClampsPoolHints(t *testing.T) {
	id := testsupport.Certificates(t)
	q := url.Values{"sni": {"node.test"}, "pin": {id.Pin}, "certificate": {base64.StdEncoding.EncodeToString(id.Server)}, "path": {"/hyraken.pro/Tunnel"}, "transport": {"auto"}, "suite": {"chacha20-poly1305"}, "congestion": {"beast"}, "connections": {"8"}, "elastic_mux": {"1"}, "packet_encoding": {"xudp"}, "traffic_profile": {"gaming"}, "engine": {"ghostx"}, "isolation": {"1"}}
	config, err := Parse("hyraken-pro://0123456789abcdef0123456789abcdef@node.test:443?" + q.Encode())
	if err != nil {
		t.Fatalf("valid synthetic Pro node rejected: %v", err)
	}
	if config.Protocol != "hyraken-pro" || config.Path != "/hyraken.pro/Tunnel" || config.PacketEncoding != "xudp" || config.Suite != "chacha20-poly1305" || config.TLS.InsecureSkipVerify || config.Connections != 1 || config.ElasticMux {
		t.Fatal("Pro security/wire options or hard mobile pool policy changed")
	}
}

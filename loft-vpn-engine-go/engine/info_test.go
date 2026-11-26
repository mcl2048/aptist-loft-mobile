package engine

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// A ready flag or omitted source boundary would let the service describe an
// unlinked transport as usable. These are consumer contract assertions.
func TestRuntimeInfoReportsUnavailableReviewedTransports(t *testing.T) {
	raw := RuntimeInfo()
	if len(raw) > 65536 {
		t.Fatalf("description exceeds the control response limit: %d", len(raw))
	}
	var info struct {
		SchemaVersion  int    `json:"schema_version"`
		EngineVersion  string `json:"engine_version"`
		TransportReady bool   `json:"transport_ready"`
		Unavailable    string `json:"unavailable_reason"`
		GatewayPin     string `json:"gateway_source_pin"`
		Protocols      []struct {
			ID           string `json:"id"`
			Linked       bool   `json:"mobile_linked"`
			UDPMin       int    `json:"udp_payload_min"`
			UDPMax       int    `json:"udp_payload_max"`
			EnvelopeMax  int    `json:"udp_envelope_max"`
			UDPTransport string `json:"udp_transport"`
		} `json:"reviewed_protocols"`
	}
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		t.Fatalf("description is not JSON: %v", err)
	}
	if info.SchemaVersion != 1 || info.EngineVersion == "" {
		t.Fatalf("missing versioned description: %+v", info)
	}
	if info.TransportReady || info.Unavailable != "loft.engine.data_plane_unavailable" {
		t.Fatalf("unlinked data plane reported ready: %+v", info)
	}
	if info.GatewayPin != "231f14813f2b45cb6f0bde984181c57cba1d02fd" {
		t.Fatalf("incorrect reviewed Gateway source: %q", info.GatewayPin)
	}
	want := map[string]struct {
		min, max, envelope int
		transport          string
	}{
		"hyrakenx":    {1, 1024, 0, "fixed_target_reliable_stream"},
		"hyraken-pro": {0, 65507, 66023, "reliable_tcp_or_custom_grpc"},
	}
	for _, protocol := range info.Protocols {
		if protocol.Linked {
			t.Errorf("%s is described as linked", protocol.ID)
		}
		limits, ok := want[protocol.ID]
		if !ok {
			t.Errorf("unexpected protocol %q", protocol.ID)
			continue
		}
		if protocol.UDPMin != limits.min || protocol.UDPMax != limits.max || protocol.EnvelopeMax != limits.envelope || protocol.UDPTransport != limits.transport {
			t.Errorf("incorrect %s payload/transport boundary: %+v", protocol.ID, protocol)
		}
		delete(want, protocol.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing reviewed protocols: %+v", want)
	}
}

// A missing pin, incomplete payload distinction or implicit linked claim would
// make a source review look like a tested Android implementation.
func TestSourceLockIdentifiesUnlinkedPinnedProtocolInputs(t *testing.T) {
	raw := SourceLock()
	if len(raw) > 65536 {
		t.Fatalf("source lock exceeds control response limit: %d", len(raw))
	}
	var lock struct {
		SchemaVersion int `json:"schema_version"`
		Gateway       struct {
			Commit string `json:"commit"`
			Linked bool   `json:"linked_into_mobile_data_plane"`
			Files  []struct {
				Path   string `json:"path"`
				SHA256 string `json:"sha256"`
			} `json:"files"`
		} `json:"gateway"`
		Mobile struct {
			TUN     bool `json:"tun_adapter_implemented"`
			Protect bool `json:"socket_protect_implemented"`
			Ready   bool `json:"transport_ready"`
		} `json:"mobile"`
	}
	if err := json.Unmarshal([]byte(raw), &lock); err != nil {
		t.Fatalf("source lock is not valid JSON: %v", err)
	}
	if lock.SchemaVersion != 1 || lock.Gateway.Commit != "231f14813f2b45cb6f0bde984181c57cba1d02fd" {
		t.Fatalf("source inputs lack the reviewed schema/commit: %+v", lock)
	}
	if lock.Gateway.Linked || lock.Mobile.TUN || lock.Mobile.Protect || lock.Mobile.Ready {
		t.Fatalf("source lock promises an unimplemented data plane: %+v", lock)
	}
	required := map[string]bool{
		"modules/hyrakenx/quic.go":                         true,
		"modules/hyrakenx/packetconn.go":                   true,
		"GhostX-core-main/protocol/hyrakenx/hyrakenx.go":   true,
		"pkg/hyrakenpro/transport.go":                      true,
		"pkg/hyrakenpro/xudp.go":                           true,
		"GhostX-core-main/protocol/hyrakenpro/outbound.go": true,
	}
	for _, file := range lock.Gateway.Files {
		digest, err := hex.DecodeString(file.SHA256)
		if err != nil || len(digest) != 32 {
			t.Errorf("source %q has no SHA256 digest", file.Path)
		}
		if strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "..") {
			t.Errorf("source path is not repository relative: %q", file.Path)
		}
		delete(required, file.Path)
	}
	if len(required) != 0 {
		t.Fatalf("source lock omits reviewed protocol adapters: %+v", required)
	}
}

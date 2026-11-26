// Package engine exposes legacy local control and a real protected VPN adapter
// for gomobile. Rust remains the authority for client business state.
package engine

import (
	_ "embed"
	"encoding/json"
)

const (
	schemaVersion       = 1
	engineVersion       = "0.1.2-LYNX"
	gatewaySourcePin    = "231f14813f2b45cb6f0bde984181c57cba1d02fd"
	maxOperations       = 64
	maxReservedBytes    = int64(8 * 1024 * 1024)
	maxOperationMillis  = int64(30000)
	maxDrainMillis      = int64(5000)
	maxDescriptionBytes = 64 * 1024
)

//go:embed source-lock.json
var sourceLockJSON string

type reviewedProtocol struct {
	ID           string `json:"id"`
	MobileLinked bool   `json:"mobile_linked"`
	UDPMin       int    `json:"udp_payload_min"`
	UDPMax       int    `json:"udp_payload_max"`
	EnvelopeMax  int    `json:"udp_envelope_max"`
	UDPTransport string `json:"udp_transport"`
}

type controlLimits struct {
	ActiveOperations       int   `json:"active_operations"`
	ReservedBytes          int64 `json:"reserved_bytes"`
	OperationDeadlineMaxMS int64 `json:"operation_deadline_max_ms"`
	DrainDeadlineMaxMS     int64 `json:"drain_deadline_max_ms"`
	DescriptionMaxBytes    int   `json:"description_max_bytes"`
}

func limits() controlLimits {
	return controlLimits{maxOperations, maxReservedBytes, maxOperationMillis, maxDrainMillis, maxDescriptionBytes}
}

// RuntimeInfo describes the preserved legacy control API as versioned JSON.
// reviewed_protocols describes pinned upstream inputs, not linked transports.
// Its values never depend on imported nodes, endpoints or credentials.
func RuntimeInfo() string {
	info := struct {
		SchemaVersion     int                `json:"schema_version"`
		EngineVersion     string             `json:"engine_version"`
		TransportReady    bool               `json:"transport_ready"`
		UnavailableReason string             `json:"unavailable_reason"`
		GatewaySourcePin  string             `json:"gateway_source_pin"`
		ControlOnly       bool               `json:"control_runtime_only"`
		Limits            controlLimits      `json:"limits"`
		Protocols         []reviewedProtocol `json:"reviewed_protocols"`
	}{
		SchemaVersion:     schemaVersion,
		EngineVersion:     engineVersion,
		UnavailableReason: "loft.engine.data_plane_unavailable",
		GatewaySourcePin:  gatewaySourcePin,
		ControlOnly:       true,
		Limits:            limits(),
		Protocols: []reviewedProtocol{
			{"hyrakenx", false, 1, 1024, 0, "fixed_target_reliable_stream"},
			{"hyraken-pro", false, 0, 65507, 66023, "reliable_tcp_or_custom_grpc"},
		},
	}
	return descriptionJSON(info)
}

// SourceLock returns the legacy controller review manifest without credentials.
// The real VPN adapter inventory is third_party/SOURCE-LOCK.json and its compiled
// capabilities are exposed separately by VPNRuntimeInfo.
func SourceLock() string {
	return sourceLockJSON
}

func descriptionJSON(value any) string {
	encoded, err := json.Marshal(value)
	// All callers marshal fixed schemas with scalar metadata. Treat an internal
	// schema programming error as an invariant violation rather than valid JSON.
	if err != nil || len(encoded) > maxDescriptionBytes {
		panic("loft.engine.invalid_internal_description")
	}
	return string(encoded)
}

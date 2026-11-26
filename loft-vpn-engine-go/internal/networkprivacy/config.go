// Package networkprivacy owns the shared VPN packet/flow privacy boundary.
// It contains no physical resolver or direct business dialer.
package networkprivacy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"loft.local/hydra"
)

// Policy is an immutable, Rust-authorized configuration for one captured scope.
type Policy struct {
	SchemaVersion       int          `json:"schema_version"`
	PolicyEpoch         string       `json:"policy_epoch"`
	ScopeID             string       `json:"scope_id"`
	DNSMode             string       `json:"dns_mode"`
	DNSLeakPolicy       string       `json:"dns_leak_policy"`
	WebRTCPolicy        string       `json:"webrtc_policy"`
	ResolverEndpoint    string       `json:"resolver_endpoint"`
	DNSMapMaxEntries    int          `json:"dns_map_max_entries"`
	DNSMapMaxBytes      int          `json:"dns_map_max_bytes"`
	DNSTTLSeconds       int          `json:"dns_ttl_seconds"`
	DNSMaxQueryBytes    int          `json:"dns_max_query_bytes"`
	DNSMaxResponseBytes int          `json:"dns_max_response_bytes"`
	Hydra               hydra.Config `json:"hydra"`
}

var errPolicy = errors.New("loft.vpn.invalid_network_policy")

// ParsePolicy validates bounded canonical JSON without performing any I/O.
func ParsePolicy(raw string) (Policy, error) {
	if len(raw) == 0 || len(raw) > 4096 || uniqueJSON(raw) != nil {
		return Policy{}, errPolicy
	}
	fields, err := exactObject([]byte(raw), []string{
		"schema_version", "policy_epoch", "scope_id", "dns_mode", "dns_leak_policy", "webrtc_policy", "resolver_endpoint",
		"dns_map_max_entries", "dns_map_max_bytes", "dns_ttl_seconds", "dns_max_query_bytes", "dns_max_response_bytes", "hydra",
	})
	if err != nil {
		return Policy{}, errPolicy
	}
	if _, err := exactObject(fields["hydra"], []string{
		"enabled", "auto_jitter", "rotation_seconds", "rotation_jitter_percent", "chunk_min_percent", "burst_min_records", "burst_max_records", "padding_gap_max_records",
	}); err != nil {
		return Policy{}, errPolicy
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy Policy
	if decoder.Decode(&policy) != nil || decoder.Decode(new(any)) != io.EOF {
		return Policy{}, errPolicy
	}
	return normalizePolicy(policy)
}

// exactObject precedes typed decoding because encoding/json accepts null for
// scalar fields and matches struct keys without respecting letter case.
func exactObject(raw []byte, keys []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return nil, errPolicy
	}
	for _, key := range keys {
		value, exists := fields[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errPolicy
		}
	}
	return fields, nil
}

func normalizePolicy(policy Policy) (Policy, error) {
	epoch, err := strconv.ParseUint(policy.PolicyEpoch, 10, 64)
	if err != nil || epoch == 0 || strconv.FormatUint(epoch, 10) != policy.PolicyEpoch || policy.SchemaVersion != 1 || len(policy.ScopeID) != 64 {
		return Policy{}, errPolicy
	}
	for _, character := range policy.ScopeID {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return Policy{}, errPolicy
		}
	}
	if policy.DNSMode != "node_domain_fake_ip" && policy.DNSMode != "wire_tcp" ||
		policy.DNSLeakPolicy != "proxy_only" && policy.DNSLeakPolicy != "block" ||
		policy.WebRTCPolicy != "proxy_only" && policy.WebRTCPolicy != "block" {
		return Policy{}, errPolicy
	}
	if policy.DNSMapMaxEntries < 1 || policy.DNSMapMaxEntries > 256 || policy.DNSMapMaxBytes < policy.DNSMapMaxEntries*1024 || policy.DNSMapMaxBytes > 262144 ||
		policy.DNSTTLSeconds < 1 || policy.DNSTTLSeconds > 60 || policy.DNSMaxQueryBytes < 12 || policy.DNSMaxQueryBytes > 4096 || policy.DNSMaxResponseBytes < 12 || policy.DNSMaxResponseBytes > 65535 {
		return Policy{}, errPolicy
	}
	if policy.DNSMode == "node_domain_fake_ip" {
		if policy.ResolverEndpoint != "" {
			return Policy{}, errPolicy
		}
	} else {
		host, port, err := net.SplitHostPort(policy.ResolverEndpoint)
		address, addressErr := netip.ParseAddr(host)
		number, portErr := strconv.Atoi(port)
		if err != nil || addressErr != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() || portErr != nil || number < 1 || number > 65535 {
			return Policy{}, errPolicy
		}
	}
	policy.Hydra, err = hydra.Normalize(policy.Hydra)
	if err != nil {
		return Policy{}, errPolicy
	}
	return policy, nil
}

// uniqueJSON rejects duplicate keys at every level before typed decoding.
func uniqueJSON(raw string) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 5 {
			return errPolicy
		}
		token, err := decoder.Token()
		if err != nil {
			return errPolicy
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return errPolicy
				}
				if _, duplicate := seen[name]; duplicate {
					return errPolicy
				}
				seen[name] = struct{}{}
				if value(depth+1) != nil {
					return errPolicy
				}
			}
		case '[':
			for decoder.More() {
				if value(depth+1) != nil {
					return errPolicy
				}
			}
		default:
			return errPolicy
		}
		if _, err := decoder.Token(); err != nil {
			return errPolicy
		}
		return nil
	}
	if value(0) != nil {
		return errPolicy
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errPolicy
	}
	return nil
}

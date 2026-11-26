package networkprivacy_test

import (
	"encoding/json"
	"strings"
	"testing"

	privacy "net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
)

const policyJSON = `{"schema_version":1,"policy_epoch":"1","scope_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dns_mode":"node_domain_fake_ip","dns_leak_policy":"proxy_only","webrtc_policy":"proxy_only","resolver_endpoint":"","dns_map_max_entries":256,"dns_map_max_bytes":262144,"dns_ttl_seconds":60,"dns_max_query_bytes":4096,"dns_max_response_bytes":65535,"hydra":{"enabled":false,"auto_jitter":false,"rotation_seconds":300,"rotation_jitter_percent":0,"chunk_min_percent":0,"burst_min_records":0,"burst_max_records":0,"padding_gap_max_records":0}}`

func testPolicy(t *testing.T, changes map[string]any) privacy.Policy {
	t.Helper()
	var values map[string]any
	if err := json.Unmarshal([]byte(policyJSON), &values); err != nil {
		t.Fatal(err)
	}
	for key, value := range changes {
		values[key] = value
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := privacy.ParsePolicy(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestPolicyPreservesExactEpochAndMandatoryModes(t *testing.T) {
	policy := testPolicy(t, map[string]any{"policy_epoch": "18446744073709551615"})
	if policy.PolicyEpoch != "18446744073709551615" || policy.DNSMode != "node_domain_fake_ip" || policy.DNSLeakPolicy != "proxy_only" || policy.WebRTCPolicy != "proxy_only" || policy.Hydra.Enabled {
		t.Fatal("policy lost exact epoch or mandatory defaults")
	}
}

func TestPolicyRejectsUnknownDuplicateAndUnsafeValues(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown":                strings.Replace(policyJSON, `"schema_version":1`, `"schema_version":1,"extra":true`, 1),
		"duplicate":              strings.Replace(policyJSON, `"policy_epoch":"1"`, `"policy_epoch":"1","policy_epoch":"2"`, 1),
		"nested_duplicate":       strings.Replace(policyJSON, `"enabled":false`, `"enabled":false,"enabled":true`, 1),
		"numeric_epoch":          strings.Replace(policyJSON, `"policy_epoch":"1"`, `"policy_epoch":1`, 1),
		"epoch_zero":             strings.Replace(policyJSON, `"policy_epoch":"1"`, `"policy_epoch":"0"`, 1),
		"epoch_noncanonical":     strings.Replace(policyJSON, `"policy_epoch":"1"`, `"policy_epoch":"01"`, 1),
		"allow_dns":              strings.Replace(policyJSON, `"dns_leak_policy":"proxy_only"`, `"dns_leak_policy":"allow"`, 1),
		"off_rtc":                strings.Replace(policyJSON, `"webrtc_policy":"proxy_only"`, `"webrtc_policy":"off"`, 1),
		"too_many_maps":          strings.Replace(policyJSON, `"dns_map_max_entries":256`, `"dns_map_max_entries":257`, 1),
		"insufficient_map_bytes": strings.Replace(policyJSON, `"dns_map_max_bytes":262144`, `"dns_map_max_bytes":1024`, 1),
		"large_query":            strings.Replace(policyJSON, `"dns_max_query_bytes":4096`, `"dns_max_query_bytes":4097`, 1),
		"long_ttl":               strings.Replace(policyJSON, `"dns_ttl_seconds":60`, `"dns_ttl_seconds":61`, 1),
		"fake_endpoint":          strings.Replace(policyJSON, `"resolver_endpoint":""`, `"resolver_endpoint":"9.9.9.9:53"`, 1),
		"trailing":               policyJSON + `{}`,
		"oversize":               strings.Repeat(" ", 4097) + policyJSON,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := privacy.ParsePolicy(raw); err == nil {
				t.Fatal("unsafe or ambiguous policy accepted")
			}
		})
	}
}

func TestWireModeRequiresAnExplicitLiteralEndpoint(t *testing.T) {
	for _, address := range []string{"", "resolver.invalid:53", "[::1]:53", "9.9.9.9:0"} {
		raw := strings.Replace(strings.Replace(policyJSON, `"dns_mode":"node_domain_fake_ip"`, `"dns_mode":"wire_tcp"`, 1), `"resolver_endpoint":""`, `"resolver_endpoint":"`+address+`"`, 1)
		if _, err := privacy.ParsePolicy(raw); err == nil {
			t.Fatal("wire mode accepted an unavailable endpoint contract")
		}
	}
	policy := testPolicy(t, map[string]any{"dns_mode": "wire_tcp", "resolver_endpoint": "9.9.9.9:53"})
	if policy.ResolverEndpoint != "9.9.9.9:53" {
		t.Fatal("explicit wire endpoint changed")
	}
}

func TestPolicyRequiresEveryExactTypedKeyIncludingFalseAndZero(t *testing.T) {
	var baseline map[string]any
	if err := json.Unmarshal([]byte(policyJSON), &baseline); err != nil {
		t.Fatal(err)
	}
	for key := range baseline {
		for _, mutation := range []string{"missing", "null", "case", "case_pair"} {
			t.Run(key+"_"+mutation, func(t *testing.T) {
				var values map[string]any
				if err := json.Unmarshal([]byte(policyJSON), &values); err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "missing":
					delete(values, key)
				case "null":
					values[key] = nil
				case "case":
					values[strings.ToUpper(key)] = values[key]
					delete(values, key)
				case "case_pair":
					values[strings.ToUpper(key)] = values[key]
				}
				raw, err := json.Marshal(values)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := privacy.ParsePolicy(string(raw)); err == nil {
					t.Fatal("missing/null/case-alias key accepted")
				}
			})
		}
	}
	for key := range baseline["hydra"].(map[string]any) {
		for _, mutation := range []string{"missing", "null", "case", "case_pair"} {
			t.Run("hydra_"+key+"_"+mutation, func(t *testing.T) {
				var values map[string]any
				if err := json.Unmarshal([]byte(policyJSON), &values); err != nil {
					t.Fatal(err)
				}
				fields := values["hydra"].(map[string]any)
				switch mutation {
				case "missing":
					delete(fields, key)
				case "null":
					fields[key] = nil
				case "case":
					fields[strings.ToUpper(key)] = fields[key]
					delete(fields, key)
				case "case_pair":
					fields[strings.ToUpper(key)] = fields[key]
				}
				raw, err := json.Marshal(values)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := privacy.ParsePolicy(string(raw)); err == nil {
					t.Fatal("Hydra false/zero field defaulted instead of exact validation")
				}
			})
		}
	}
}

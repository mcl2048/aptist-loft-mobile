package engine

import (
	"encoding/json"
	"testing"
)

type deniedProtector struct{}

func (*deniedProtector) Protect(int32) bool        { return false }
func (*deniedProtector) ResolveNode(string) string { return "" }

func TestGeneratedNetworkPolicyPortKeepsInactiveFactsUntilActualStart(t *testing.T) {
	protector := &deniedProtector{}
	r, err := NewVPNRuntime(protector)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	policy := `{"schema_version":1,"policy_epoch":"1","scope_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dns_mode":"node_domain_fake_ip","dns_leak_policy":"proxy_only","webrtc_policy":"proxy_only","resolver_endpoint":"","dns_map_max_entries":256,"dns_map_max_bytes":262144,"dns_ttl_seconds":60,"dns_max_query_bytes":4096,"dns_max_response_bytes":65535,"hydra":{"enabled":false,"auto_jitter":false,"rotation_seconds":300,"rotation_jitter_percent":0,"chunk_min_percent":0,"burst_min_records":0,"burst_max_records":0,"padding_gap_max_records":0}}`
	if err := r.SetNetworkPolicy(policy); err != nil {
		t.Fatal(err)
	}
	var facts map[string]any
	if json.Unmarshal([]byte(r.Snapshot()), &facts) != nil || facts["policy_installed"] != true || facts["enforcement_active"] != false {
		t.Fatal("policy port fabricated active privacy")
	}
}

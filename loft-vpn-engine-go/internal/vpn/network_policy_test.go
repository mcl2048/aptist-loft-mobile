package vpn

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/transport"
)

const testNetworkPolicyJSON = `{"schema_version":1,"policy_epoch":"1","scope_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dns_mode":"node_domain_fake_ip","dns_leak_policy":"proxy_only","webrtc_policy":"proxy_only","resolver_endpoint":"","dns_map_max_entries":256,"dns_map_max_bytes":262144,"dns_ttl_seconds":60,"dns_max_query_bytes":4096,"dns_max_response_bytes":65535,"hydra":{"enabled":false,"auto_jitter":false,"rotation_seconds":300,"rotation_jitter_percent":0,"chunk_min_percent":0,"burst_min_records":0,"burst_max_records":0,"padding_gap_max_records":0}}`

func testPolicyJSON(t *testing.T, changes map[string]any) string {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(testNetworkPolicyJSON), &fields); err != nil {
		t.Fatal(err)
	}
	for key, value := range changes {
		fields[key] = value
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func testPrivacyPolicy(t *testing.T, changes map[string]any) networkprivacy.Policy {
	t.Helper()
	policy, err := networkprivacy.ParsePolicy(testPolicyJSON(t, changes))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testWirePolicy(t *testing.T, endpoint string) networkprivacy.Policy {
	return testPrivacyPolicy(t, map[string]any{"dns_mode": "wire_tcp", "resolver_endpoint": endpoint})
}

func configuredTestRuntime(t *testing.T, platform transport.SocketPolicy, endpoint string) *Runtime {
	t.Helper()
	r := NewRuntime(platform)
	if err := r.SetNetworkPolicy(testPolicyJSON(t, map[string]any{"dns_mode": "wire_tcp", "resolver_endpoint": endpoint})); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNetworkPolicyInstallsInertlyWithoutFabricatingActiveProof(t *testing.T) {
	platform := &inertPolicy{}
	r := NewRuntime(platform)
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := r.SetNetworkPolicy(testNetworkPolicyJSON); err != nil {
		t.Fatal(err)
	}
	var facts map[string]any
	if json.Unmarshal([]byte(r.SnapshotJSON()), &facts) != nil {
		t.Fatal("snapshot invalid")
	}
	if facts["policy_installed"] != true || facts["policy_epoch"] != "1" || facts["dns_mode"] != "node_domain_fake_ip" || facts["enforcement_active"] != false || facts["dns_protection_enforced"] != false || facts["webrtc_protection_enforced"] != false || platform.calls.Load() != 0 {
		t.Fatal("inert policy fabricated active protection or networking")
	}
	if err := r.SetNetworkPolicy(strings.Replace(testNetworkPolicyJSON, `"dns_leak_policy":"proxy_only"`, `"dns_leak_policy":"allow"`, 1)); err == nil {
		t.Fatal("unsafe policy accepted")
	}
	if err := r.SetDNSUpstream("9.9.9.9:53"); err == nil {
		t.Fatal("legacy endpoint setter changed an immutable fake-IP policy")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal([]byte(r.SnapshotJSON()), &facts) != nil || facts["enforcement_active"] != false || facts["runtime_state"] != "closed" {
		t.Fatal("closed policy retained active proof")
	}
}

func TestStartRequiresPolicyBeforeConstructingAnySession(t *testing.T) {
	r := NewRuntime(&inertPolicy{})
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	called := false
	create := func(context.Context, *nodeconfig.Config, netip.Prefix, int, networkprivacy.Policy, func(string)) (*session, error) {
		called = true
		return nil, nil
	}
	if err := r.start("socks5://127.0.0.1:1080", "198.18.0.1/30", 1280, create); err == nil || errorCode(err) != "loft.vpn.network_policy_required" || called {
		t.Fatal("unconfigured runtime constructed a data-plane owner")
	}
}

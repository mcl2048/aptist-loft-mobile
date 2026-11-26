package engine

import (
	"context"
	"errors"
	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/vpn"
	"net/netip"
	"runtime"
	"strings"
)

// SocketProtector belongs to the private Android VpnService. Protect must call
// VpnService.protect AND bind to its captured underlying Network before connect.
// ResolveNode returns <=8 literal IPv4 addresses/newline, <=1024B, within5s.
type SocketProtector interface {
	Protect(fd int32) bool
	ResolveNode(hostname string) string
}

// VPNStateListener receives bounded immutable resource facts. It must enqueue
// promptly to the service actor and retain the snapshot's captured generation.
type VPNStateListener interface{ OnStateChanged(snapshot string) }

// VPNRuntime owns the real TUN/protocol resource boundary; Rust owns business state.
type VPNRuntime struct{ native *vpn.Runtime }

// NewVPNRuntime creates an inert real-VPN owner with mandatory Android callbacks.
func NewVPNRuntime(protector SocketProtector) (*VPNRuntime, error) {
	if protector == nil {
		return nil, errors.New("loft.vpn.invalid_platform")
	}
	return &VPNRuntime{native: vpn.NewRuntime(&androidPolicy{protector})}, nil
}

// SetDNSUpstream retains legacy validation; an installed policy is immutable.
func (r *VPNRuntime) SetDNSUpstream(address string) error {
	if r.native == nil {
		return errors.New("loft.vpn.invalid_platform")
	}
	return r.native.SetDNSUpstream(address)
}

// SetNetworkPolicy installs the current Rust-authorized DNS/WebRTC/Hydra scope.
// Validation is idle-only and performs no resolution, socket or TUN work.
func (r *VPNRuntime) SetNetworkPolicy(canonicalJSON string) error {
	if r.native == nil {
		return errors.New("loft.vpn.invalid_platform")
	}
	return r.native.SetNetworkPolicy(canonicalJSON)
}

// Start duplicates a verified TUN fd and starts only after protected authentication.
func (r *VPNRuntime) Start(fd int32, rawNode, tunIPv4Prefix string, mtu int32) error {
	if r.native == nil {
		return errors.New("loft.vpn.invalid_platform")
	}
	return r.native.Start(int(fd), rawNode, tunIPv4Prefix, int(mtu))
}

// Snapshot returns only resource facts, never node/authentication material.
func (r *VPNRuntime) Snapshot() string {
	if r.native == nil {
		return descriptionJSON(vpn.Snapshot{Facts: networkprivacy.PolicyFacts(nil), SchemaVersion: 1, State: "unavailable", ForwardingDisabled: true, ResourcesReleased: true})
	}
	return r.native.SnapshotJSON()
}

// Drain freezes actual flow admission and bounds remaining work at1..5000ms.
func (r *VPNRuntime) Drain(ms int64) error {
	if r.native == nil {
		return errors.New("loft.vpn.invalid_platform")
	}
	return r.native.Drain(ms)
}

// Abort disables forwarding and closes protocol work; Android retains its original fd.
func (r *VPNRuntime) Abort() error {
	if r.native == nil {
		return nil
	}
	return r.native.Abort()
}

// Stop closes the Go-owned dup, protocol resources and workers with a real receipt.
func (r *VPNRuntime) Stop() error {
	if r.native == nil {
		return nil
	}
	return r.native.Stop()
}

// Close terminates this owner; unconfirmed completion remains an explicit error.
func (r *VPNRuntime) Close() error {
	if r.native == nil {
		return nil
	}
	return r.native.Close()
}

// SetStateListener installs one coalesced state/loss consumer outside owner locks.
func (r *VPNRuntime) SetStateListener(listener VPNStateListener) {
	if r.native == nil {
		return
	}
	if listener == nil {
		r.native.SetListener(nil)
	} else {
		r.native.SetListener(listener.OnStateChanged)
	}
}

type androidPolicy struct{ protector SocketProtector }

func (p *androidPolicy) Protect(fd int) error {
	if fd < 0 || !p.protector.Protect(int32(fd)) {
		return errors.New("loft.vpn.socket_protect_failed")
	}
	return nil
}
func (p *androidPolicy) Resolve(ctx context.Context, hostname string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.New("loft.vpn.node_resolution_canceled")
	}
	if ip, err := netip.ParseAddr(hostname); err == nil {
		if !ip.Is4() {
			return nil, errors.New("loft.vpn.ipv6_unavailable")
		}
		return []netip.Addr{ip}, nil
	}
	raw := p.protector.ResolveNode(hostname)
	if ctx.Err() != nil || len(raw) == 0 || len(raw) > 1024 {
		return nil, errors.New("loft.vpn.node_resolution_failed")
	}
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) > 8 {
		return nil, errors.New("loft.vpn.node_resolution_failed")
	}
	addresses := make([]netip.Addr, 0, len(lines))
	for _, line := range lines {
		ip, err := netip.ParseAddr(strings.TrimSpace(line))
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("loft.vpn.node_resolution_failed")
		}
		addresses = append(addresses, ip)
	}
	return addresses, nil
}

// VPNRuntimeInfo reports compiled implementation capabilities, not an active VPN.
func VPNRuntimeInfo() string {
	return descriptionJSON(struct {
		SchemaVersion   int    `json:"schema_version"`
		Scope           string `json:"schema_scope"`
		EngineVersion   string `json:"engine_version"`
		SourcePin       string `json:"gateway_source_pin"`
		GVisor          bool   `json:"gvisor_built"`
		DataPlaneLinked bool   `json:"linked_into_mobile_data_plane"`
		GoMaxProcs      int    `json:"gomaxprocs"`
		TransportReady  bool   `json:"transport_ready"`
		IPv6            bool   `json:"ipv6_forwarded"`
		DNSMode         string `json:"dns_mode"`
	}{SchemaVersion: 1, Scope: "vpn_transport_runtime", EngineVersion: engineVersion, SourcePin: gatewaySourcePin, GVisor: vpn.GVisorBuilt, DataPlaneLinked: vpn.GVisorBuilt, GoMaxProcs: runtime.GOMAXPROCS(0), DNSMode: "node_domain_fake_ip"})
}

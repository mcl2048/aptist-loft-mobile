package networkprivacy

import (
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ProxySource is the actual selected adapter, never a caller-supplied route flag.
// Future transports share this boundary instead of installing another runtime.
type ProxySource interface {
	PrivacyReady() bool
	PrivacyDone() <-chan struct{}
}

type TransportDetails struct {
	NodeResolverCalls, BusinessResolverCalls int64
	HydraApplied                             bool
	HydraScope                               string
	HydraShapedRecords, HydraPaddingBytes    int64
}

// Facts separates configuration, active enforcement and actual query outcomes.
type Facts struct {
	PolicyInstalled          bool   `json:"policy_installed"`
	PolicyEpoch              string `json:"policy_epoch"`
	ScopeID                  string `json:"scope_id"`
	DNSMode                  string `json:"dns_mode"`
	DNSLeakPolicy            string `json:"dns_leak_policy"`
	WebRTCPolicy             string `json:"webrtc_policy"`
	EnforcementActive        bool   `json:"enforcement_active"`
	DNSProtectionEnforced    bool   `json:"dns_protection_enforced"`
	WebRTCProtectionEnforced bool   `json:"webrtc_protection_enforced"`
	IPv6DropActive           bool   `json:"ipv6_drop_active"`
	DNSMapEntries            int    `json:"dns_map_entries"`
	DNSMapBytes              int64  `json:"dns_map_bytes"`
	DNSAllocatorBytes        int64  `json:"dns_allocator_bytes"`
	DNSSyntheticCount        int64  `json:"dns_synthetic_count"`
	DNSValidatedWireCount    int64  `json:"dns_validated_wire_count"`
	DNSPolicyDropCount       int64  `json:"dns_policy_drop_count"`
	WebRTCClassifiedCount    int64  `json:"webrtc_classified_count"`
	WebRTCPolicyDropCount    int64  `json:"webrtc_policy_drop_count"`
	NodeResolverCalls        int64  `json:"node_resolver_calls"`
	BusinessResolverCalls    int64  `json:"business_resolver_calls"`
	HydraEnabled             bool   `json:"hydra_enabled"`
	HydraApplied             bool   `json:"hydra_applied"`
	HydraScope               string `json:"hydra_scope"`
	HydraShapedRecords       int64  `json:"hydra_shaped_records"`
	HydraPaddingBytes        int64  `json:"hydra_padding_bytes"`
}

func PolicyFacts(policy *Policy) Facts {
	if policy == nil {
		return Facts{HydraScope: "off", DNSAllocatorBytes: DNSAllocatorBytes}
	}
	return Facts{PolicyInstalled: true, PolicyEpoch: policy.PolicyEpoch, ScopeID: policy.ScopeID, DNSMode: policy.DNSMode,
		DNSLeakPolicy: policy.DNSLeakPolicy, WebRTCPolicy: policy.WebRTCPolicy, HydraEnabled: policy.Hydra.Enabled, HydraScope: "off", DNSAllocatorBytes: DNSAllocatorBytes}
}

// Enforcer owns one private client/policy identity and the common mapping/guards.
// There are no background workers, resolver defaults or physical business exits.
type Enforcer struct {
	mu                                                 sync.Mutex
	policy                                             Policy
	budget                                             Budget
	source                                             ProxySource
	mapping                                            *Map
	active, retired                                    bool
	flows                                              int
	synthetic, wire, dnsDrops, rtcClassified, rtcDrops atomic.Int64
}

func New(policy Policy, budget Budget, source ProxySource) (*Enforcer, error) {
	if budget == nil || source == nil {
		return nil, errPolicy
	}
	validated, err := normalizePolicy(policy)
	if err != nil {
		return nil, err
	}
	return &Enforcer{policy: validated, budget: budget, source: source, mapping: NewMap(validated, budget)}, nil
}

func (e *Enforcer) sourceReady() bool {
	if !e.source.PrivacyReady() {
		return false
	}
	select {
	case <-e.source.PrivacyDone():
		return false
	default:
		return true
	}
}

// Activate may only commit after the owner installed its packet/DNS path and
// the actual selected adapter authenticated. A later lost source revokes proof.
func (e *Enforcer) Activate() error {
	if !e.sourceReady() {
		return errors.New("loft.vpn.privacy_not_active")
	}
	if e.policy.Hydra.Enabled {
		if source, ok := e.source.(interface{ PrivacyDetails() TransportDetails }); !ok || !source.PrivacyDetails().HydraApplied {
			return errors.New("loft.vpn.hydra_policy_not_applied")
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retired {
		return errors.New("loft.vpn.privacy_retired")
	}
	e.active = true
	return nil
}

func (e *Enforcer) Current() bool {
	e.mu.Lock()
	active := e.active && !e.retired
	e.mu.Unlock()
	return active && e.sourceReady()
}

// Revoke is nonblocking: pending I/O is canceled/joined by the VPN owner, while
// new admission/proof is withdrawn immediately and mapping borrowers stay owned.
func (e *Enforcer) Revoke() {
	e.mu.Lock()
	e.active = false
	e.retired = true
	e.mu.Unlock()
	e.mapping.Close()
}

func (e *Enforcer) Snapshot() Facts {
	facts := PolicyFacts(&e.policy)
	facts.EnforcementActive = e.Current()
	facts.DNSProtectionEnforced = facts.EnforcementActive
	facts.WebRTCProtectionEnforced = facts.EnforcementActive
	facts.DNSMapEntries, facts.DNSMapBytes = e.mapping.Usage()
	facts.DNSSyntheticCount = e.synthetic.Load()
	facts.DNSValidatedWireCount = e.wire.Load()
	facts.DNSPolicyDropCount = e.dnsDrops.Load()
	facts.WebRTCClassifiedCount = e.rtcClassified.Load()
	facts.WebRTCPolicyDropCount = e.rtcDrops.Load()
	if source, ok := e.source.(interface{ PrivacyDetails() TransportDetails }); ok {
		details := source.PrivacyDetails()
		facts.NodeResolverCalls, facts.BusinessResolverCalls = details.NodeResolverCalls, details.BusinessResolverCalls
		facts.HydraApplied = facts.EnforcementActive && e.policy.Hydra.Enabled && details.HydraApplied
		if facts.HydraApplied {
			facts.HydraScope = details.HydraScope
		}
		facts.HydraShapedRecords, facts.HydraPaddingBytes = details.HydraShapedRecords, details.HydraPaddingBytes
	}
	return facts
}

func increment(counter *atomic.Int64) {
	for {
		old := counter.Load()
		if old == math.MaxInt64 || counter.CompareAndSwap(old, old+1) {
			return
		}
	}
}

// Flow retains fixed classifier state and an optional original synthetic lease.
// Its unexported owner identity cannot be supplied by app packet metadata.
type Flow struct {
	mu                     sync.Mutex
	owner                  *Enforcer
	target, original, host string
	port                   int
	mapping                *MappingLease
	dnsSeen, rtcSeen       bool
	dnsProbe               dnsTCPProbe
	rtcProbe               webRTCStreamProbe
	pending                [273]byte
	pendingLength          int
	replyDNSProbe          dnsTCPProbe
	replyRTCProbe          webRTCStreamProbe
	replyPending           [273]byte
	replyPendingLength     int
	closed                 atomic.Bool
	once                   sync.Once
}

func (e *Enforcer) NewFlow(network, target string, now time.Time) (*Flow, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("loft.vpn.privacy_network_unsupported")
	}
	return e.newFlow(target, now, false)
}

// NewDNSFlow is used by the trusted local DNS adapter, never an OPEN wire verb.
func (e *Enforcer) NewDNSFlow(target string, now time.Time) (*Flow, error) {
	return e.newFlow(target, now, true)
}

func (e *Enforcer) newFlow(target string, now time.Time, dnsAdapter bool) (*Flow, error) {
	if !e.Current() {
		return nil, errors.New("loft.vpn.privacy_not_active")
	}
	host, portText, err := net.SplitHostPort(target)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || len(host) > 253 {
		return nil, errors.New("loft.vpn.privacy_invalid_target")
	}
	e.mu.Lock()
	if !e.active || e.retired || e.flows >= 64 || !e.budget.ReservePacket(4096) {
		e.mu.Unlock()
		return nil, errors.New("loft.vpn.privacy_flow_limit")
	}
	e.flows++
	e.mu.Unlock()
	flow := &Flow{owner: e, target: target, original: target, host: host, port: port}
	flow.replyDNSProbe.responses = true
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() {
			flow.Close()
			return nil, errors.New("loft.vpn.ipv6_unavailable")
		}
		if fakePrefix.Contains(address) {
			lease, err := e.mapping.Borrow(address, now)
			if err != nil {
				flow.Close()
				return nil, err
			}
			flow.mapping = lease
			flow.host = lease.Host()
			flow.target = net.JoinHostPort(flow.host, portText)
		}
	}
	if !dnsAdapter && (port == 53 || port == 853 || isEncryptedDNSHost(flow.host)) && e.policy.DNSLeakPolicy == "block" {
		increment(&e.dnsDrops)
		flow.Close()
		return nil, errors.New("loft.vpn.dns_policy_denied")
	}
	if (isWebRTCServicePort(port) || isWebRTCServiceHost(flow.host)) && e.policy.WebRTCPolicy == "block" {
		increment(&e.rtcDrops)
		flow.Close()
		return nil, errors.New("loft.vpn.webrtc_policy_denied")
	}
	if !e.Current() {
		flow.Close()
		return nil, errors.New("loft.vpn.privacy_not_active")
	}
	return flow, nil
}

func (f *Flow) Target() string   { return f.target }
func (f *Flow) Original() string { return f.original }
func (f *Flow) Mapped() bool     { return f.mapping != nil }

func (f *Flow) Close() {
	f.once.Do(func() {
		f.closed.Store(true)
		f.mapping.Close()
		f.owner.mu.Lock()
		f.owner.flows--
		f.owner.mu.Unlock()
		f.owner.budget.ReleasePacket(4096)
	})
}

func (f *Flow) Current() bool { return !f.closed.Load() && f.owner.Current() }

func (f *Flow) InspectUDP(packet []byte) error {
	return f.inspectUDP(packet, false)
}

func (f *Flow) inspectUDP(packet []byte, reply bool) error {
	if !f.Current() {
		return errors.New("loft.vpn.privacy_not_active")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if isDNSQuery(packet) || reply && isDNSQuestion(packet) {
		f.dnsSeen = true
	}
	hint := isWebRTCServicePort(f.port) || isWebRTCServiceHost(f.host)
	kind, _ := classifyWebRTCDatagram(packet, hint, f.rtcSeen)
	if kind == "" && f.owner.policy.WebRTCPolicy == "block" && looksLikeDTLSClientHello(packet) {
		kind = "dtls"
	}
	if kind != "" && !f.rtcSeen {
		increment(&f.owner.rtcClassified)
		f.rtcSeen = true
	}
	return f.decisionLocked()
}

// InspectReply keeps classified association identity for replies and empty UDP.
func (f *Flow) InspectReply(packet []byte) error { return f.inspectUDP(packet, true) }

func (f *Flow) decisionLocked() error {
	if f.dnsSeen && f.owner.policy.DNSLeakPolicy == "block" {
		increment(&f.owner.dnsDrops)
		return errors.New("loft.vpn.dns_policy_denied")
	}
	if f.rtcSeen && f.owner.policy.WebRTCPolicy == "block" {
		increment(&f.owner.rtcDrops)
		return errors.New("loft.vpn.webrtc_policy_denied")
	}
	return nil
}

// WriteTo inspects reassembled TCP bytes before forwarding them. Strict block
// retains only the fixed undecided prefix; proxy_only never delays ordinary I/O.
// No classifier or enforcer lock is held while the actual writer can block.
func (f *Flow) WriteTo(writer io.Writer, packet []byte) (int, error) {
	return f.writeTCP(writer, packet, false)
}

func (f *Flow) WriteReplyTo(writer io.Writer, packet []byte) (int, error) {
	return f.writeTCP(writer, packet, true)
}

func (f *Flow) writeTCP(writer io.Writer, packet []byte, reply bool) (int, error) {
	if !f.Current() {
		return 0, errors.New("loft.vpn.privacy_not_active")
	}
	f.mu.Lock()
	dnsProbe, rtcProbe, pending, pendingLength := &f.dnsProbe, &f.rtcProbe, &f.pending, &f.pendingLength
	if reply {
		dnsProbe, rtcProbe, pending, pendingLength = &f.replyDNSProbe, &f.replyRTCProbe, &f.replyPending, &f.replyPendingLength
	}
	dnsProbe.feed(packet)
	_, rtc, _ := rtcProbe.feed(packet)
	if dnsProbe.detected {
		f.dnsSeen = true
	}
	if rtc && !f.rtcSeen {
		f.rtcSeen = true
		increment(&f.owner.rtcClassified)
	}
	if err := f.decisionLocked(); err != nil {
		f.mu.Unlock()
		return 0, err
	}
	wait := f.owner.policy.DNSLeakPolicy == "block" && !dnsProbe.done || f.owner.policy.WebRTCPolicy == "block" && !rtcProbe.decided
	if wait {
		if *pendingLength+len(packet) > len(pending) {
			f.mu.Unlock()
			return 0, errors.New("loft.vpn.privacy_prefix_limit")
		}
		*pendingLength += copy(pending[*pendingLength:], packet)
		f.mu.Unlock()
		return len(packet), nil
	}
	var previous [273]byte
	prefix := copy(previous[:], pending[:*pendingLength])
	*pendingLength = 0
	f.mu.Unlock()
	if !f.Current() {
		return 0, errors.New("loft.vpn.privacy_not_active")
	}
	if prefix != 0 {
		if err := writeFully(writer, previous[:prefix]); err != nil {
			return 0, err
		}
	}
	if err := writeFully(writer, packet); err != nil {
		return 0, err
	}
	return len(packet), nil
}

// FinishTCP flushes a short unclassified ordinary prefix only on actual EOF.
// Identified DNS/RTC remains denied, and opposite receive state is independent.
func (f *Flow) FinishTCP(writer io.Writer, reply bool) error {
	if !f.Current() {
		return errors.New("loft.vpn.privacy_not_active")
	}
	f.mu.Lock()
	if err := f.decisionLocked(); err != nil {
		f.mu.Unlock()
		return err
	}
	pending, length := &f.pending, &f.pendingLength
	if reply {
		pending, length = &f.replyPending, &f.replyPendingLength
	}
	var prefix [273]byte
	n := copy(prefix[:], pending[:*length])
	*length = 0
	f.mu.Unlock()
	if !f.Current() {
		return errors.New("loft.vpn.privacy_not_active")
	}
	return writeFully(writer, prefix[:n])
}

func writeFully(writer io.Writer, packet []byte) error {
	for len(packet) > 0 {
		n, err := writer.Write(packet)
		if n < 0 || n > len(packet) {
			return io.ErrShortWrite
		}
		packet = packet[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

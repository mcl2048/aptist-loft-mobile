// Package vpn owns the mobile TUN, bounded forwarding and lifecycle receipts.
package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/transport"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Snapshot is immutable credential-free resource evidence for Rust reconciliation.
type Snapshot struct {
	networkprivacy.Facts
	SchemaVersion      int    `json:"schema_version"`
	Generation         int64  `json:"generation"`
	State              string `json:"runtime_state"`
	TransportReady     bool   `json:"transport_ready"`
	Authenticated      bool   `json:"authenticated"`
	TunReady           bool   `json:"tun_ready"`
	TunOwned           bool   `json:"tun_owned"`
	SocketProtection   bool   `json:"socket_protection_succeeded"`
	ForwardingDisabled bool   `json:"forwarding_disabled"`
	ResourcesReleased  bool   `json:"resources_released"`
	OwnershipPending   bool   `json:"ownership_pending"`
	PhysicalOpen       int    `json:"physical_open"`
	ActiveFlows        int    `json:"active_flows"`
	QueuedBytes        int64  `json:"queued_bytes"`
	ErrorCode          string `json:"error_code,omitempty"`
}

// Runtime owns one current VPN resource generation.
type Runtime struct {
	mu            sync.Mutex
	policy        transport.SocketPolicy
	networkPolicy *networkprivacy.Policy
	finalPrivacy  *networkprivacy.Facts
	finalTraffic  *trafficUsage
	state         string
	generation    int64
	session       *session
	pendingCancel context.CancelFunc
	startDone     chan struct{}
	stopOp        *stopOperation
	abortOp       *stopOperation
	drainOp       *stopOperation
	closed        bool
	lastError     string
	listener      func(string)
	notify        chan string
	notifyStarted bool
	notifyStop    chan struct{}
	notifyDone    chan struct{}
	notifyClosing bool
	notifyEnded   bool
}

type stopOperation struct {
	done chan struct{}
	err  error
}

// NewRuntime constructs inert control state without resolving or dialing.
func NewRuntime(policy transport.SocketPolicy) *Runtime {
	return &Runtime{policy: policy, state: "idle", notify: make(chan string, 1), notifyStop: make(chan struct{}), notifyDone: make(chan struct{})}
}

// SetNetworkPolicy validates the complete Rust-frozen policy without I/O.
// An active, pending or retiring session keeps its original policy identity.
func (r *Runtime) SetNetworkPolicy(raw string) error {
	policy, err := networkprivacy.ParsePolicy(raw)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.startDone != nil || r.session != nil || r.stopOp != nil || r.abortOp != nil || r.drainOp != nil {
		return errors.New("loft.vpn.settings_busy")
	}
	r.networkPolicy = &policy
	r.finalPrivacy = nil
	r.finalTraffic = nil
	return nil
}

// SetDNSUpstream retains idle legacy endpoint validation. It cannot install or
// alter an authorized policy; Start uses only canonical SetNetworkPolicy input.
func (r *Runtime) SetDNSUpstream(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("loft.vpn.invalid_dns_upstream")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("loft.vpn.invalid_dns_upstream")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("loft.vpn.invalid_dns_upstream")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.startDone != nil || r.session != nil || r.stopOp != nil {
		return errors.New("loft.vpn.settings_busy")
	}
	if r.networkPolicy != nil {
		return errors.New("loft.vpn.network_policy_immutable")
	}
	return nil
}

// Start consumes a real TUN receipt and authenticates a protected protocol.
func (r *Runtime) Start(fd int, raw, prefix string, mtu int) error {
	return r.start(raw, prefix, mtu, func(ctx context.Context, cfg *nodeconfig.Config, address netip.Prefix, mtu int, networkPolicy networkprivacy.Policy, lost func(string)) (*session, error) {
		dup, name, err := duplicateTUN(fd)
		if err != nil {
			return nil, err
		}
		return startSession(ctx, dup, name, address, mtu, cfg, r.policy, networkPolicy, lost)
	})
}

// start owns validation and generation fencing independently of the platform
// TUN constructor. Start always supplies verified descriptor duplication.
func (r *Runtime) start(raw, prefix string, mtu int, create func(context.Context, *nodeconfig.Config, netip.Prefix, int, networkprivacy.Policy, func(string)) (*session, error)) error {
	r.mu.Lock()
	if r.closed || r.session != nil || r.startDone != nil || r.stopOp != nil {
		r.mu.Unlock()
		return errors.New("loft.vpn.already_running_or_closed")
	}
	if r.networkPolicy == nil {
		r.mu.Unlock()
		return errors.New("loft.vpn.network_policy_required")
	}
	r.finalPrivacy = nil
	r.finalTraffic = nil
	r.generation++
	generation := r.generation
	r.state = "starting"
	r.lastError = ""
	ctx, cancel := context.WithCancel(context.Background())
	r.pendingCancel = cancel
	done := make(chan struct{})
	r.startDone = done
	networkPolicy := *r.networkPolicy
	r.mu.Unlock()
	r.publish()
	var result error
	defer func() {
		r.mu.Lock()
		if r.generation == generation {
			r.pendingCancel = nil
			r.startDone = nil
			if result != nil && r.state == "starting" {
				r.state = "failed"
				r.lastError = errorCode(result)
			}
		}
		close(done)
		r.mu.Unlock()
		if result != nil {
			cancel()
		}
		r.publish()
	}()
	cfg, err := nodeconfig.Parse(raw)
	if err != nil {
		result = err
		return result
	}
	defer clear(cfg.Seed)
	if cfg.Protocol == "socks5" && networkPolicy.Hydra.Enabled {
		result = errors.New("loft.vpn.hydra_unsupported_transport")
		return result
	}
	address, err := netip.ParsePrefix(prefix)
	if err != nil || !address.Addr().Is4() || address.Addr().IsUnspecified() || address.Bits() != 30 || mtu != 1280 {
		result = errors.New("loft.vpn.invalid_tun_configuration")
		return result
	}
	created, err := create(ctx, cfg, address, mtu, networkPolicy, func(code string) { r.lost(generation, code) })
	if err != nil {
		if created != nil {
			r.mu.Lock()
			r.session = created
			r.state = "failed"
			r.lastError = errorCode(err)
			r.mu.Unlock()
		}
		result = err
		return result
	}
	r.mu.Lock()
	if r.closed || r.generation != generation || r.state != "starting" || ctx.Err() != nil {
		r.mu.Unlock()
		if err := created.stop(); err != nil {
			r.mu.Lock()
			r.session = created
			r.lastError = errorCode(err)
			r.state = "failed"
			r.mu.Unlock()
			result = err
			return result
		}
		result = errors.New("loft.vpn.start_canceled")
		return result
	}
	r.session = created
	r.state = "running"
	r.mu.Unlock()
	r.publish()
	return nil
}

// Snapshot returns current resource facts without node material.
func (r *Runtime) Snapshot() Snapshot {
	r.mu.Lock()
	snapshot := Snapshot{SchemaVersion: 1, Generation: r.generation, State: r.state, ForwardingDisabled: true, ResourcesReleased: r.session == nil && r.startDone == nil, OwnershipPending: r.startDone != nil, ErrorCode: r.lastError}
	snapshot.Facts = networkprivacy.PolicyFacts(r.networkPolicy)
	if r.finalPrivacy != nil && r.networkPolicy != nil && r.finalPrivacy.PolicyEpoch == r.networkPolicy.PolicyEpoch && r.finalPrivacy.ScopeID == r.networkPolicy.ScopeID {
		snapshot.Facts = *r.finalPrivacy
	}
	current := r.session
	joining := r.startDone != nil || r.stopOp != nil || r.abortOp != nil || r.drainOp != nil || (r.closed && r.notifyStarted && !r.notifyEnded)
	r.mu.Unlock()
	if current != nil {
		current.facts(&snapshot)
	}
	if joining {
		snapshot.ResourcesReleased = false
	}
	if snapshot.OwnershipPending {
		snapshot.ForwardingDisabled = false
	}
	return snapshot
}

// SnapshotJSON serializes bounded reconciliation facts.
func (r *Runtime) SnapshotJSON() string { raw, _ := json.Marshal(r.Snapshot()); return string(raw) }

// Drain freezes admission and waits for existing forwarding owners.
func (r *Runtime) Drain(ms int64) error {
	if ms < 1 || ms > 5000 {
		return errors.New("loft.vpn.invalid_drain_timeout")
	}
	r.mu.Lock()
	current := r.session
	if current == nil || r.closed || r.state != "running" || r.stopOp != nil || r.abortOp != nil || r.drainOp != nil {
		r.mu.Unlock()
		return errors.New("loft.vpn.not_running")
	}
	r.state = "draining"
	operation := &stopOperation{done: make(chan struct{})}
	r.drainOp = operation
	r.mu.Unlock()
	r.publish()
	go r.completeDrain(operation, current, time.Duration(ms)*time.Millisecond)
	select {
	case <-operation.done:
		return operation.err
	case <-time.After(time.Duration(ms)*time.Millisecond + 5*time.Second):
		r.mu.Lock()
		if r.drainOp != operation {
			err := operation.err
			r.mu.Unlock()
			return err
		}
		r.lastError = "loft.vpn.drain_timeout"
		r.mu.Unlock()
		r.publish()
		return errors.New("loft.vpn.drain_timeout")
	}
}

func (r *Runtime) completeDrain(operation *stopOperation, current *session, timeout time.Duration) {
	err := current.drain(timeout)
	r.mu.Lock()
	if r.session == current && r.stopOp == nil {
		r.state = "blocked"
		if err != nil {
			r.lastError = errorCode(err)
		}
	}
	operation.err = err
	r.drainOp = nil
	close(operation.done)
	r.mu.Unlock()
	r.publish()
}

// Abort bounds the caller at five seconds while an owned completion disables
// forwarding and joins protocol/copy work, retaining TUN ownership until Stop.
func (r *Runtime) Abort() error {
	r.mu.Lock()
	current := r.session
	cancel := r.pendingCancel
	if current == nil {
		r.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		r.publish()
		return nil
	}
	if r.stopOp != nil {
		r.mu.Unlock()
		current.signalCancellation()
		if cancel != nil {
			cancel()
		}
		r.publish()
		return nil
	}
	if r.state != "failed" {
		r.state = "blocked"
	}
	operation := r.abortOp
	first := operation == nil
	if first {
		operation = &stopOperation{done: make(chan struct{})}
		r.abortOp = operation
	}
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	current.signalCancellation()
	r.publish()
	if first {
		go r.completeAbort(operation, current)
	}
	select {
	case <-operation.done:
		return operation.err
	case <-time.After(5 * time.Second):
		r.mu.Lock()
		if r.abortOp != operation {
			err := operation.err
			r.mu.Unlock()
			return err
		}
		r.lastError = "loft.vpn.abort_timeout"
		r.mu.Unlock()
		r.publish()
		return errors.New("loft.vpn.abort_timeout")
	}
}

func (r *Runtime) completeAbort(operation *stopOperation, current *session) {
	current.abort()
	current.waitForwarding()
	r.mu.Lock()
	if r.session == current && r.stopOp == nil && r.lastError == "loft.vpn.abort_timeout" {
		r.lastError = ""
	}
	operation.err = nil
	r.abortOp = nil
	close(operation.done)
	r.mu.Unlock()
	r.publish()
}

// Stop cancels and closes owned TUN/protocol/workers.
func (r *Runtime) Stop() error {
	r.mu.Lock()
	if r.stopOp == nil && r.session == nil && r.startDone == nil && (!r.closed || !r.notifyStarted || r.notifyEnded) {
		if !r.closed {
			r.state = "stopped"
		} else {
			r.state = "closed"
		}
		r.mu.Unlock()
		r.publish()
		return nil
	}
	operation := r.stopOp
	if operation == nil {
		r.state = "stopping"
		current, starting, cancel := r.session, r.startDone, r.pendingCancel
		operation = &stopOperation{done: make(chan struct{})}
		r.stopOp = operation
		r.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if current != nil {
			current.signalCancellation()
		}
		r.publish()
		go r.completeStop(operation, current, starting)
	} else {
		r.mu.Unlock()
	}
	select {
	case <-operation.done:
		return operation.err
	case <-time.After(5 * time.Second):
		r.mu.Lock()
		if r.stopOp != operation {
			err := operation.err
			r.mu.Unlock()
			return err
		}
		r.lastError = "loft.vpn.stop_timeout"
		r.mu.Unlock()
		r.publish()
		return errors.New("loft.vpn.stop_timeout")
	}
}

func (r *Runtime) completeStop(operation *stopOperation, current *session, starting <-chan struct{}) {
	var err error
	released := current == nil
	if current != nil {
		err = current.stop()
		var proof Snapshot
		current.facts(&proof)
		released = proof.ResourcesReleased
		if !released && err == nil {
			err = errors.New("loft.vpn.release_unconfirmed")
		}
	}
	if starting != nil {
		<-starting
		if current == nil {
			r.mu.Lock()
			current = r.session
			r.mu.Unlock()
			if current != nil {
				err = current.stop()
				var proof Snapshot
				current.facts(&proof)
				released = proof.ResourcesReleased
				if !released && err == nil {
					err = errors.New("loft.vpn.release_unconfirmed")
				}
			}
		}
	}
	r.mu.Lock()
	aborting := r.abortOp
	r.mu.Unlock()
	if aborting != nil {
		<-aborting.done
	}
	r.mu.Lock()
	draining := r.drainOp
	r.mu.Unlock()
	if draining != nil {
		<-draining.done
	}
	if notified := r.terminateNotifications(); notified != nil {
		<-notified
	}
	var final *networkprivacy.Facts
	if current != nil && released && err == nil {
		var proof Snapshot
		current.facts(&proof)
		if proof.ResourcesReleased && proof.QueuedBytes == 0 && proof.ActiveFlows == 0 && proof.PhysicalOpen == 0 && proof.DNSMapEntries == 0 && proof.DNSMapBytes == 0 && !proof.OwnershipPending {
			facts := proof.Facts
			facts.EnforcementActive, facts.DNSProtectionEnforced, facts.WebRTCProtectionEnforced, facts.IPv6DropActive, facts.HydraApplied = false, false, false, false, false
			facts.HydraScope = "off"
			final = &facts
		}
	}
	r.mu.Lock()
	if r.session == current && released && err == nil {
		if final != nil && r.networkPolicy != nil && final.PolicyEpoch == r.networkPolicy.PolicyEpoch && final.ScopeID == r.networkPolicy.ScopeID {
			r.finalPrivacy = final
			totals := current.traffic.sample()
			r.finalTraffic = &totals
		}
		r.session = nil
	}
	if err != nil || !released {
		r.state = "failed"
	} else if r.closed {
		r.state = "closed"
	} else {
		r.state = "stopped"
	}
	r.lastError = errorCode(err)
	operation.err = err
	r.stopOp = nil
	close(operation.done)
	r.mu.Unlock()
	r.publish()
}

// Close permanently terminates this owner.
func (r *Runtime) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	err := r.Stop()
	if err == nil {
		r.mu.Lock()
		r.state = "closed"
		r.mu.Unlock()
		r.publish()
	}
	return err
}

// SetListener registers one bounded asynchronous state consumer.
func (r *Runtime) SetListener(listener func(string)) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.listener = listener
	if listener != nil && !r.notifyStarted {
		r.notifyStarted = true
		go r.deliver()
	}
	r.mu.Unlock()
	r.publish()
}

func (r *Runtime) publish() {
	raw := r.SnapshotJSON()
	r.mu.Lock()
	enabled := r.listener != nil && !r.notifyClosing
	r.mu.Unlock()
	if !enabled {
		return
	}
	select {
	case r.notify <- raw:
	default:
		select {
		case <-r.notify:
		default:
		}
		select {
		case r.notify <- raw:
		default:
		}
	}
}
func (r *Runtime) deliver() {
	defer func() {
		r.mu.Lock()
		r.notifyEnded = true
		close(r.notifyDone)
		r.mu.Unlock()
	}()
	for {
		var raw string
		select {
		case <-r.notifyStop:
			return
		case raw = <-r.notify:
		}
		r.mu.Lock()
		listener := r.listener
		r.mu.Unlock()
		if listener != nil {
			listener(raw)
		}
	}
}

func (r *Runtime) terminateNotifications() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		return nil
	}
	r.listener = nil
	if !r.notifyStarted {
		return nil
	}
	if !r.notifyClosing {
		r.notifyClosing = true
		close(r.notifyStop)
	}
	return r.notifyDone
}
func (r *Runtime) lost(generation int64, code string) {
	r.mu.Lock()
	if r.generation != generation || (r.state != "running" && r.state != "starting") {
		r.mu.Unlock()
		return
	}
	current := r.session
	cancel := r.pendingCancel
	r.state = "failed"
	r.lastError = code
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if current != nil {
		current.abort()
	}
	r.publish()
}
func errorCode(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) < 100 && len(value) >= 9 && value[:9] == "loft.vpn." {
		return value
	}
	return "loft.vpn.operation_failed"
}

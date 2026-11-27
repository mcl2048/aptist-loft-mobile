//go:build with_gvisor

package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	x "loft.local/hyrakenx"
	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/transport"
)

const GVisorBuilt = true

const (
	maxUDPPayload      = 65507
	fullUDPBufferBytes = 65536
)

type flowKey struct {
	network             uint8
	source, destination netip.AddrPort
}
type forwardFlow struct {
	key          flowKey
	lease        *ByteLease
	cancel       context.CancelFunc
	ctx          context.Context
	timer        *time.Timer
	claimed      bool
	app          net.Conn
	remote       net.Conn
	packet       N.PacketConn
	remotePacket net.PacketConn
	guard        *networkprivacy.Flow
	once         sync.Once
}
type session struct {
	mu                         sync.Mutex
	ctx                        context.Context
	cancel                     context.CancelFunc
	client                     *transport.Client
	privacy                    *networkprivacy.Enforcer
	networkPolicy              networkprivacy.Policy
	tun                        tun.Tun
	stack                      tun.Stack
	observed                   *observedTUN
	budget                     *ByteBudget
	traffic                    trafficCounters
	flows                      map[flowKey]*forwardFlow
	idle                       chan struct{}
	wg                         sync.WaitGroup
	monitorWG                  sync.WaitGroup
	enabled, started, tunOwned bool
	released                   bool
	dns                        string
	udpBytes                   int64
	udpDownstreamSize          int
	synthetic                  netip.Addr
	lost                       func(string)
	stopOnce                   sync.Once
	stopErr                    error
	lossOnce                   sync.Once
	stackCloseOnce             sync.Once
	stackCloseErr              error
}

func startSession(ctx context.Context, fd int, name string, address netip.Prefix, mtu int, cfg *nodeconfig.Config, policy transport.SocketPolicy, networkPolicy networkprivacy.Policy, lost func(string)) (*session, error) {
	options := tun.Options{Name: name, FileDescriptor: fd, Inet4Address: []netip.Prefix{address}, MTU: uint32(mtu), AutoRoute: false, GSO: false, EXP_ExternalConfiguration: true, DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true, Logger: logger.NOP()}
	native, err := tun.New(options)
	if err != nil {
		_ = unix.Close(fd)
		return nil, errors.New("loft.vpn.tun_open_failed")
	}
	return startWithTun(ctx, native, options, cfg, policy, networkPolicy, lost)
}

func startWithTun(parent context.Context, native tun.Tun, options tun.Options, cfg *nodeconfig.Config, policy transport.SocketPolicy, networkPolicy networkprivacy.Policy, lost func(string)) (*session, error) {
	ctx, cancel := context.WithCancel(parent)
	idle := make(chan struct{})
	close(idle)
	udpDownstreamSize, udpDownstreamBytes := maxUDPPayload, fullUDPBufferBytes
	if cfg != nil && cfg.Protocol == "hyrakenx" {
		// X's framing rejects larger remote datagrams before copying to the
		// caller. The TUN reader still needs its full buffer to consume a local
		// oversized packet without terminating the active association.
		udpDownstreamSize, udpDownstreamBytes = x.MaxDatagramPayload, x.MaxDatagramPayload
	}
	udpBytes := int64(fullUDPBufferBytes + udpDownstreamBytes + 512)
	if cfg != nil && cfg.Protocol == "socks5" {
		udpBytes += fullUDPBufferBytes
	}
	s := &session{
		ctx: ctx, cancel: cancel, tun: native, tunOwned: true,
		budget: NewBudget(networkprivacy.DynamicBudgetBytes), flows: make(map[flowKey]*forwardFlow), idle: idle,
		dns: networkPolicy.ResolverEndpoint, networkPolicy: networkPolicy, udpBytes: udpBytes, udpDownstreamSize: udpDownstreamSize,
		synthetic: options.Inet4Address[0].Addr().Next(), lost: lost,
	}
	client, err := transport.NewClientWithOptions(ctx, cfg, policy, transport.ClientOptions{Hydra: networkPolicy.Hydra})
	if err != nil {
		return s.startupFailure("loft.vpn.invalid_node")
	}
	s.client = client
	s.privacy, err = networkprivacy.New(networkPolicy, s.budget, client)
	if err != nil {
		return s.startupFailure("loft.vpn.invalid_network_policy")
	}
	opening, stop := context.WithTimeout(ctx, 15*time.Second)
	err = client.Ready(opening)
	stop()
	if err != nil {
		return s.startupFailure("loft.vpn.node_authentication_failed")
	}
	gTun, ok := native.(tun.GVisorTun)
	if !ok {
		return s.startupFailure("loft.vpn.invalid_gvisor_tun")
	}
	s.observed = &observedTUN{GVisorTun: gTun}
	if err := native.Start(); err != nil {
		return s.startupFailure("loft.vpn.tun_start_failed")
	}
	stack, err := tun.NewStack("gvisor", tun.StackOptions{Context: ctx, Tun: s.observed, TunOptions: options, UDPTimeout: 30 * time.Second, ICMPTimeout: 5 * time.Second, UDPMapping: tun.NATMappingAddressAndPortDependent, UDPFiltering: tun.NATFilteringAddressAndPortDependent, UDPNATMax: 64, Handler: s, Logger: logger.NOP(), MobileLimits: true, PacketQueueSlots: 16, PacketMemoryBudget: s.budget})
	if err != nil {
		return s.startupFailure("loft.vpn.stack_create_failed")
	}
	s.stack = stack
	if err := stack.Start(); err != nil {
		return s.startupFailure("loft.vpn.stack_start_failed")
	}
	if s.observed.filter == nil || !s.observed.filter.active.Load() {
		return s.startupFailure("loft.vpn.ipv6_filter_not_installed")
	}
	if err := s.privacy.Activate(); err != nil {
		return s.startupFailure("loft.vpn.privacy_not_active")
	}
	s.mu.Lock()
	s.enabled = true
	s.started = true
	s.mu.Unlock()
	s.monitorWG.Add(1)
	go func() {
		defer s.monitorWG.Done()
		select {
		case <-client.Lost():
			s.signalLoss(client.LossCode())
		case <-s.ctx.Done():
		}
	}()
	// The observed real fd-based reader exits on descriptor/network loss. This
	// monitor uses endpoint completion, never a timer pretending to connect.
	if s.observed.endpoint != nil {
		s.monitorWG.Add(1)
		go func() {
			defer s.monitorWG.Done()
			s.observed.endpoint.Wait()
			if s.ctx.Err() == nil {
				s.signalLoss("loft.vpn.tun_reader_stopped")
			}
		}()
	}
	return s, nil
}

func (s *session) startupFailure(code string) (*session, error) {
	if err := s.stop(); err != nil {
		return s, err
	}
	return nil, errors.New(code)
}

func (s *session) signalLoss(code string) {
	s.lossOnce.Do(func() {
		s.abort()
		if s.lost != nil {
			s.lost(code)
		}
	})
}

type observedTUN struct {
	tun.GVisorTun
	endpoint stack.LinkEndpoint
	filter   *ipv4Endpoint
}

func (t *observedTUN) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	endpoint, options, err := t.GVisorTun.NewEndpoint()
	if err != nil {
		return nil, options, err
	}
	filtered := &ipv4Endpoint{LinkEndpoint: endpoint}
	t.endpoint = filtered
	t.filter = filtered
	return filtered, options, nil
}

type ipv4Endpoint struct {
	stack.LinkEndpoint
	active atomic.Bool
}

func (e *ipv4Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.active.Store(dispatcher != nil)
	if dispatcher == nil {
		e.LinkEndpoint.Attach(nil)
	} else {
		e.LinkEndpoint.Attach(&ipv4Dispatcher{dispatcher})
	}
}

type ipv4Dispatcher struct{ stack.NetworkDispatcher }

func (d *ipv4Dispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, packet *stack.PacketBuffer) {
	if protocol != header.IPv4ProtocolNumber {
		return
	}
	d.NetworkDispatcher.DeliverNetworkPacket(protocol, packet)
}

func (s *session) JudgeFlow(network uint8, source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	if !source.Addr().Is4() || !destination.Addr().Is4() {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled || s.privacy == nil || !s.privacy.Current() {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	if network == 17 && (destination.Port() == 53 || networkprivacy.IsDNSQuery(firstPacket)) {
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	}
	if network != 6 && network != 17 {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	key := flowKey{network, source, destination}
	if s.flows[key] != nil {
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	bytes := int64(2*16384 + 2*32768)
	if network == 17 {
		bytes = s.udpBytes
	}
	if len(s.flows) >= 64 {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	var guard *networkprivacy.Flow
	var err error
	if network == 6 && destination.Port() == 53 {
		guard, err = s.privacy.NewDNSFlow(destination.String(), time.Now())
	} else {
		kind := "tcp"
		if network == 17 {
			kind = "udp"
		}
		guard, err = s.privacy.NewFlow(kind, destination.String(), time.Now())
	}
	if err != nil {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	if network == 17 && guard.InspectUDP(firstPacket) != nil {
		guard.Close()
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	lease, err := s.budget.Acquire(bytes)
	if err != nil {
		guard.Close()
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	ctx, cancel := context.WithCancel(s.ctx)
	flow := &forwardFlow{key: key, lease: lease, ctx: ctx, cancel: cancel, guard: guard}
	if len(s.flows) == 0 {
		s.idle = make(chan struct{})
	}
	s.flows[key] = flow
	flow.timer = time.AfterFunc(8*time.Second, func() {
		s.mu.Lock()
		pending := s.flows[key] == flow && !flow.claimed
		s.mu.Unlock()
		if pending {
			s.finish(flow)
		}
	})
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (s *session) claim(key flowKey) *forwardFlow {
	s.mu.Lock()
	defer s.mu.Unlock()
	flow := s.flows[key]
	if !s.enabled || flow == nil || flow.claimed || flow.guard == nil || !flow.guard.Current() {
		return nil
	}
	if !flow.timer.Stop() {
		return nil
	}
	flow.claimed = true
	s.wg.Add(1)
	return flow
}
func (s *session) finish(flow *forwardFlow) {
	flow.once.Do(func() {
		flow.cancel()
		s.mu.Lock()
		app, remote, packet, remotePacket := flow.app, flow.remote, flow.packet, flow.remotePacket
		s.mu.Unlock()
		if app != nil {
			_ = app.Close()
		}
		if remote != nil {
			_ = remote.Close()
		}
		if packet != nil {
			_ = packet.Close()
		}
		if remotePacket != nil {
			_ = remotePacket.Close()
		}
		flow.timer.Stop()
		if flow.guard != nil {
			flow.guard.Close()
		}
		flow.lease.Close()
		s.mu.Lock()
		if s.flows[flow.key] == flow {
			delete(s.flows, flow.key)
			if len(s.flows) == 0 {
				close(s.idle)
			}
		}
		claimed := flow.claimed
		s.mu.Unlock()
		if claimed {
			s.wg.Done()
		}
	})
}

func (s *session) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	flow := s.claim(flowKey{6, source.AddrPort(), destination.AddrPort()})
	if flow == nil {
		_ = conn.Close()
		return
	}
	defer s.finish(flow)
	s.mu.Lock()
	flow.app = conn
	s.mu.Unlock()
	if destination.Port == 53 {
		s.serveDNSStream(flow, conn)
		return
	}
	target := flow.guard.Target()
	opening, cancel := context.WithTimeout(flow.ctx, 8*time.Second)
	remote, err := s.client.DialTCP(opening, target)
	cancel()
	if err != nil {
		return
	}
	s.mu.Lock()
	flow.remote = remote
	s.mu.Unlock()
	stop := context.AfterFunc(flow.ctx, func() { _ = conn.Close(); _ = remote.Close() })
	defer stop()
	results := make(chan error, 2)
	copySide := func(dst, src net.Conn, reply bool) {
		buffer := make([]byte, 16384)
		defer clear(buffer)
		counter := &s.traffic.upload
		if reply {
			counter = &s.traffic.download
		}
		writer := &trafficWriter{destination: dst, counter: counter}
		_, err := io.CopyBuffer(guardedWriter{flow.guard, writer, reply}, src, buffer)
		if err == nil {
			err = flow.guard.FinishTCP(writer, reply)
		}
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			} else {
				err = errors.New("loft.vpn.half_close_unsupported")
			}
		}
		results <- err
	}
	go copySide(remote, conn, false)
	go copySide(conn, remote, true)
	remaining := 2
	select {
	case err := <-results:
		remaining--
		if err != nil {
			_ = conn.Close()
			_ = remote.Close()
		}
	case <-flow.ctx.Done():
		_ = conn.Close()
		_ = remote.Close()
	}
	if remaining == 2 {
		if err := <-results; err != nil {
			_ = conn.Close()
			_ = remote.Close()
		}
	}
	select {
	case err := <-results:
		if err != nil {
			_ = conn.Close()
			_ = remote.Close()
		}
	case <-time.After(5 * time.Second):
		_ = conn.Close()
		_ = remote.Close()
		if err := <-results; err != nil {
			flow.cancel()
		}
	case <-flow.ctx.Done():
		_ = conn.Close()
		_ = remote.Close()
		if err := <-results; err != nil {
			flow.cancel()
		}
	}
}

type guardedWriter struct {
	guard  *networkprivacy.Flow
	writer io.Writer
	reply  bool
}

func (w guardedWriter) Write(packet []byte) (int, error) {
	if w.reply {
		return w.guard.WriteReplyTo(w.writer, packet)
	}
	return w.guard.WriteTo(w.writer, packet)
}

func (s *session) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	flow := s.claim(flowKey{17, source.AddrPort(), destination.AddrPort()})
	if flow == nil {
		_ = conn.Close()
		return
	}
	defer s.finish(flow)
	s.mu.Lock()
	flow.packet = conn
	s.mu.Unlock()
	targetName := flow.guard.Target()
	mapped := flow.guard.Mapped()
	var proxyTarget, appTarget M.Socksaddr
	if mapped {
		proxyTarget = M.ParseSocksaddr(targetName)
		appTarget = M.SocksaddrFromNetIP(flow.key.destination)
	}
	opening, cancel := context.WithTimeout(flow.ctx, 8*time.Second)
	remote, err := s.client.DialPacket(opening, targetName)
	cancel()
	if err != nil {
		return
	}
	s.mu.Lock()
	flow.remotePacket = remote
	s.mu.Unlock()
	stop := context.AfterFunc(flow.ctx, func() { _ = conn.Close(); _ = remote.Close() })
	defer stop()
	results := make(chan error, 2)
	go func() {
		buffer := buf.NewSize(maxUDPPayload)
		defer buffer.Release()
		for {
			buffer.Reset()
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			target, err := conn.ReadPacket(buffer)
			if err != nil {
				results <- err
				return
			}
			// The flow key already holds the native IPv4 destination confirmed
			// at admission, so the per-datagram check needs no string conversion.
			if !flow.guard.Current() || !target.IsIPv4() || target.AddrPort() != flow.key.destination {
				results <- errors.New("loft.vpn.udp_target_changed")
				return
			}
			if err := flow.guard.InspectUDP(buffer.Bytes()); err != nil {
				if privacyPolicyDrop(err) {
					// Retain this admitted association's classification. Closing it
					// would let a later empty/TURN packet recreate an unclassified
					// tuple. Its existing idle deadline and Stop own final release.
					continue
				}
				results <- err
				return
			}
			if mapped {
				target = proxyTarget
			}
			_ = remote.SetWriteDeadline(time.Now().Add(30 * time.Second))
			written, err := remote.WriteTo(buffer.Bytes(), target)
			if err != nil {
				if errorCode(err) == "loft.vpn.udp_payload_limit" {
					continue
				}
				results <- err
				return
			}
			if written == buffer.Len() {
				s.traffic.upload.record(written)
			}
		}
	}()
	go func() {
		buffer := make([]byte, s.udpDownstreamSize)
		defer clear(buffer)
		for {
			_ = remote.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, target, err := remote.ReadFrom(buffer)
			if err != nil {
				results <- err
				return
			}
			if err := flow.guard.InspectReply(buffer[:n]); err != nil {
				if privacyPolicyDrop(err) {
					continue
				}
				results <- err
				return
			}
			responseTarget := appTarget
			if !mapped {
				responseTarget = M.SocksaddrFromNet(target)
			}
			if err := conn.WritePacket(buf.As(buffer[:n]), responseTarget); err != nil {
				results <- err
				return
			}
			s.traffic.download.record(n)
		}
	}()
	remaining := 2
	select {
	case err := <-results:
		remaining--
		if err != nil {
			flow.cancel()
		}
	case <-flow.ctx.Done():
	}
	_ = conn.Close()
	_ = remote.Close()
	for i := 0; i < remaining; i++ {
		if err := <-results; err != nil {
			flow.cancel()
		}
	}
}

func privacyPolicyDrop(err error) bool {
	code := errorCode(err)
	return code == "loft.vpn.dns_policy_denied" || code == "loft.vpn.webrtc_policy_denied"
}

func (s *session) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	if len(payload) < 2 || len(payload) > s.networkPolicy.DNSMaxQueryBytes {
		return
	}
	s.mu.Lock()
	if !s.enabled || s.privacy == nil || !s.privacy.Current() || len(s.flows) >= 64 {
		s.mu.Unlock()
		return
	}
	key := flowKey{255, source.AddrPort(), destination.AddrPort()}
	if s.flows[key] != nil {
		s.mu.Unlock()
		return
	}
	guard, err := s.privacy.NewDNSFlow(destination.String(), time.Now())
	if err != nil {
		s.mu.Unlock()
		return
	}
	lease, err := s.budget.Acquire(int64(len(payload) + 512))
	if err != nil {
		guard.Close()
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
	flow := &forwardFlow{key: key, lease: lease, ctx: ctx, cancel: cancel, claimed: true, guard: guard, timer: time.NewTimer(time.Hour)}
	flow.timer.Stop()
	if len(s.flows) == 0 {
		s.idle = make(chan struct{})
	}
	s.flows[key] = flow
	s.wg.Add(1)
	s.mu.Unlock()
	query := append([]byte(nil), payload...)
	go func() {
		defer clear(query)
		defer s.finish(flow)
		response, err := guard.AnswerDNS(ctx, query, time.Now(), s.exchangeDNS)
		if err != nil {
			if ctx.Err() == nil && guard.Current() {
				failure := dnsServerFailure(query)
				_ = writer.WritePacket(buf.As(failure[:]), destination)
			}
			return
		}
		defer response.Close()
		if ctx.Err() == nil && guard.Current() {
			if writer.WritePacket(buf.As(response.Packet), destination) == nil {
				s.privacy.ConfirmDNS(response)
			}
		}
	}()
}

func dnsServerFailure(query []byte) [12]byte {
	var response [12]byte
	if len(query) >= 2 {
		copy(response[:2], query[:2])
	}
	response[2], response[3] = 0x80, byte(dnsmessage.RCodeServerFailure)
	return response
}

func (s *session) serveDNSStream(flow *forwardFlow, conn net.Conn) {
	stop := context.AfterFunc(flow.ctx, func() { _ = conn.Close() })
	defer stop()
	for flow.guard.Current() && flow.ctx.Err() == nil {
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(prefix[:]))
		if size < 2 || size > s.networkPolicy.DNSMaxQueryBytes {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(conn, query); err != nil {
			clear(query)
			return
		}
		ctx, cancel := context.WithTimeout(flow.ctx, 8*time.Second)
		answer, err := flow.guard.AnswerDNS(ctx, query, time.Now(), s.exchangeDNS)
		cancel()
		if err != nil {
			failure := dnsServerFailure(query)
			clear(query)
			if !flow.guard.Current() || flow.ctx.Err() != nil {
				return
			}
			binary.BigEndian.PutUint16(prefix[:], uint16(len(failure)))
			if writeAll(conn, prefix[:]) != nil || writeAll(conn, failure[:]) != nil {
				return
			}
			continue
		}
		clear(query)
		binary.BigEndian.PutUint16(prefix[:], uint16(len(answer.Packet)))
		if !flow.guard.Current() || flow.ctx.Err() != nil || writeAll(conn, prefix[:]) != nil || writeAll(conn, answer.Packet) != nil {
			answer.Close()
			return
		}
		s.privacy.ConfirmDNS(answer)
		answer.Close()
	}
}

func (s *session) exchangeDNS(ctx context.Context, query []byte) ([]byte, error) {
	conn, err := s.client.DialTCP(ctx, s.dns)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }() // Owner cancellation may already have reset this stream; Stop joins physical resources.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	wire := make([]byte, 2+len(query))
	defer clear(wire)
	binary.BigEndian.PutUint16(wire[:2], uint16(len(query)))
	copy(wire[2:], query)
	if err := writeAll(conn, wire); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size < 12 || size > s.networkPolicy.DNSMaxResponseBytes {
		return nil, io.ErrUnexpectedEOF
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(conn, response); err != nil {
		clear(response)
		return nil, err
	}
	// The common enforcer validates ID/opcode/question/layout/RR bounds before
	// returning a distinct real-wire receipt; no physical fallback exists here.
	return response, nil
}
func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		data = data[n:]
	}
	return nil
}

func (s *session) facts(snapshot *Snapshot) {
	snapshot.Facts = networkprivacy.PolicyFacts(&s.networkPolicy)
	if s.privacy != nil {
		snapshot.Facts = s.privacy.Snapshot()
	}
	snapshot.IPv6DropActive = snapshot.EnforcementActive && s.observed != nil && s.observed.filter != nil && s.observed.filter.active.Load()
	s.mu.Lock()
	enabled, started, owned, released, count := s.enabled, s.started, s.tunOwned, s.released, len(s.flows)
	s.mu.Unlock()
	var stats transport.Statistics
	if s.client != nil {
		stats = s.client.Stats()
	}
	snapshot.Authenticated = started && stats.Ready
	snapshot.TunReady = started && owned
	snapshot.TunOwned = owned
	snapshot.SocketProtection = stats.ProtectedSockets > 0
	snapshot.PhysicalOpen = stats.PhysicalOpen
	snapshot.ActiveFlows = count
	snapshot.QueuedBytes = s.budget.Used()
	snapshot.ForwardingDisabled = !enabled && count == 0
	snapshot.TransportReady = snapshot.State == "running" && enabled && started && stats.Ready && snapshot.SocketProtection && snapshot.EnforcementActive && snapshot.IPv6DropActive
	snapshot.ResourcesReleased = released && !owned && count == 0 && stats.PhysicalOpen == 0 && snapshot.QueuedBytes == 0
}
func (s *session) abort() {
	s.mu.Lock()
	s.enabled = false
	var flows []*forwardFlow
	for _, flow := range s.flows {
		flows = append(flows, flow)
	}
	s.mu.Unlock()
	if s.privacy != nil {
		s.privacy.Revoke()
	}
	s.cancel()
	// The lazy gVisor TCP connection holds its handshake mutex until the
	// three-way handshake exits. Closing that connection first can wait on a
	// peer that never sends ACK. Stop netstack endpoints before flow closers.
	s.closeStack()
	for _, flow := range flows {
		s.mu.Lock()
		claimed, app, remote, packet, remotePacket := flow.claimed, flow.app, flow.remote, flow.packet, flow.remotePacket
		s.mu.Unlock()
		flow.cancel()
		if app != nil {
			_ = app.Close()
		}
		if remote != nil {
			_ = remote.Close()
		}
		if packet != nil {
			_ = packet.Close()
		}
		if remotePacket != nil {
			_ = remotePacket.Close()
		}
		// A claimed handler owns its buffers through its final copy/write. Only
		// its deferred finish may return those bytes and mark the worker joined.
		if !claimed {
			s.finish(flow)
		}
	}
	if s.client != nil {
		_ = s.client.Close()
	}
}

func (s *session) signalCancellation() {
	s.mu.Lock()
	s.enabled = false
	s.mu.Unlock()
	if s.privacy != nil {
		s.privacy.Revoke()
	}
	s.cancel()
}

func (s *session) waitForwarding() { s.wg.Wait() }

func (s *session) closeStack() {
	s.stackCloseOnce.Do(func() {
		if s.stack != nil {
			if err := s.stack.Close(); err != nil {
				s.stackCloseErr = errors.New("loft.vpn.stack_close_failed")
			}
		}
	})
}
func (s *session) stop() error {
	s.stopOnce.Do(func() {
		s.abort()
		var closeErr error
		if s.tun != nil {
			if err := s.tun.Close(); err != nil {
				closeErr = errors.New("loft.vpn.tun_close_failed")
			}
		}
		if s.stackCloseErr != nil && closeErr == nil {
			closeErr = s.stackCloseErr
		}
		s.wg.Wait()
		if closeErr == nil {
			if s.observed != nil && s.observed.endpoint != nil {
				s.observed.endpoint.Wait()
			}
			if waiter, ok := s.stack.(interface{ Wait() }); ok {
				waiter.Wait()
			}
			s.monitorWG.Wait()
		}
		s.mu.Lock()
		s.stopErr = closeErr
		if closeErr == nil {
			s.tunOwned = false
			s.released = true
		}
		s.started = false
		s.mu.Unlock()
	})
	return s.stopErr
}
func (s *session) drain(timeout time.Duration) error {
	s.mu.Lock()
	s.enabled = false
	idle := s.idle
	s.mu.Unlock()
	select {
	case <-idle:
		s.abort()
		return nil
	case <-time.After(timeout):
		s.abort()
		return errors.New("loft.vpn.drain_timeout")
	case <-s.ctx.Done():
		s.abort()
		return errors.New("loft.vpn.drain_canceled")
	}
}

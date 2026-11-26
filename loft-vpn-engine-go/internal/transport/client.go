// Package transport owns protected physical sockets and the pinned protocols.
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	socks "github.com/sagernet/sing/protocol/socks"
	"loft.local/ghostx-core/transport/beastprofile"
	"loft.local/hydra"
	pro "loft.local/hyrakenpro"
	x "loft.local/hyrakenx"
	"loft.local/trafficprofile"
)

import (
	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
)

// SocketPolicy owns the platform protect/Network resolution boundary.
type SocketPolicy interface {
	Protect(fd int) error
	Resolve(context.Context, string) ([]netip.Addr, error)
}

// Statistics contains only bounded resource counters.
type Statistics struct {
	PhysicalOpen, PhysicalPeak int
	ProtectedSockets           uint64
	Ready                      bool
}

// ClientOptions are immutable sender choices, independent from packet privacy.
// The zero value keeps Hydra disabled on every transport.
type ClientOptions struct{ Hydra hydra.Config }

// Client owns one selected protocol and all its physical and business resources.
type Client struct {
	mu                sync.Mutex
	readyMu           sync.Mutex
	closeOnce         sync.Once
	flowWG            sync.WaitGroup
	monitorWG         sync.WaitGroup
	ctx               context.Context
	cancel            context.CancelFunc
	cfg               *nodeconfig.Config
	policy            SocketPolicy
	options           ClientOptions
	hydraInstalled    bool
	nodeResolverCalls atomic.Int64
	shapedRecords     atomic.Int64
	paddingBytes      atomic.Int64
	addresses         []netip.Addr
	peer              *x.Peer
	proClient         *pro.Client
	socksClient       *socks.Client
	ready             bool
	closed            bool
	physical          int
	peak              int
	protected         uint64
	pendingFlows      int
	flows             map[*ownedConn]struct{}
	packetFlows       map[*ownedPacket]struct{}
	sockets           map[net.Conn]struct{}
	xSocket           net.PacketConn
	xRelease          func()
	closeErr          error
	lost              chan struct{}
	lossCode          string
}

type safeError struct {
	code  string
	cause error
}

func (e *safeError) Error() string      { return e.code }
func (e *safeError) Unwrap() error      { return e.cause }
func fail(code string, err error) error { return &safeError{"loft.vpn." + code, err} }

// NewClient creates local protocol state without initiating network I/O.
func NewClient(ctx context.Context, cfg *nodeconfig.Config, policy SocketPolicy) (*Client, error) {
	return NewClientWithOptions(ctx, cfg, policy, ClientOptions{})
}

func NewClientWithOptions(ctx context.Context, cfg *nodeconfig.Config, policy SocketPolicy, options ClientOptions) (*Client, error) {
	if ctx == nil || cfg == nil || policy == nil {
		return nil, fail("invalid_platform_or_node", nil)
	}
	if cfg.Protocol != "socks5" && (cfg.TLS == nil || cfg.TLS.InsecureSkipVerify || len(cfg.Seed) < 32) {
		return nil, fail("invalid_node", nil)
	}
	normalized, err := hydra.Normalize(options.Hydra)
	if err != nil {
		return nil, fail("invalid_network_policy", err)
	}
	options.Hydra = normalized
	if cfg.Protocol == "socks5" && options.Hydra.Enabled {
		return nil, fail("hydra_unsupported_transport", nil)
	}
	copyCfg := *cfg
	copyCfg.Seed = append([]byte(nil), cfg.Seed...)
	if cfg.TLS != nil {
		copyCfg.TLS = cfg.TLS.Clone()
	}
	owned, cancel := context.WithCancel(ctx)
	c := &Client{ctx: owned, cancel: cancel, cfg: &copyCfg, policy: policy, options: options, flows: make(map[*ownedConn]struct{}), packetFlows: make(map[*ownedPacket]struct{}), sockets: make(map[net.Conn]struct{}), lost: make(chan struct{})}
	context.AfterFunc(owned, func() { _ = c.Close() })
	return c, nil
}

// Ready authenticates the selected protocol endpoint.
func (c *Client) Ready(ctx context.Context) error {
	if ctx == nil {
		return fail("invalid_context", nil)
	}
	c.readyMu.Lock()
	defer c.readyMu.Unlock()
	owned, cancel := context.WithCancel(ctx)
	stopOwner := context.AfterFunc(c.ctx, cancel)
	defer func() { stopOwner(); cancel() }()
	ctx = owned
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil {
		c.mu.Unlock()
		return fail("closed", net.ErrClosed)
	}
	if c.ready {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fail("canceled", err)
	}
	host, _, err := net.SplitHostPort(c.cfg.Address)
	if err != nil {
		return fail("invalid_node", err)
	}
	var addresses []netip.Addr
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !literal.Is4() {
			return fail("ipv6_unavailable", nil)
		}
		addresses = []netip.Addr{literal}
	} else {
		addMetric(&c.nodeResolverCalls, 1)
		addresses, err = c.policy.Resolve(ctx, host)
	}
	if err != nil || len(addresses) == 0 || len(addresses) > 8 {
		return fail("node_resolution_failed", err)
	}
	for _, ip := range addresses {
		if !ip.IsValid() || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return fail("node_resolution_failed", nil)
		}
	}
	c.addresses = append([]netip.Addr(nil), addresses...)
	switch c.cfg.Protocol {
	case "hyrakenx":
		_, port, _ := net.SplitHostPort(c.cfg.Address)
		peer, err := x.DialWithPacketListener(ctx, net.JoinHostPort(c.addresses[0].String(), port), c.cfg.TLS, c.cfg.Seed, []x.Suite{x.SuiteRoccaS, x.SuiteChaCha20Poly1305}, c.listenX)
		if err != nil {
			c.closeXSocket()
			return fail("node_authentication_failed", err)
		}
		if err := c.configureX(peer); err != nil {
			_ = peer.Close()
			c.closeXSocket()
			return fail("sender_policy_failed", err)
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = peer.Close()
			c.closeXSocket()
			return fail("closed", net.ErrClosed)
		}
		c.peer = peer
		c.monitorWG.Add(1)
		c.mu.Unlock()
		go func() {
			defer c.monitorWG.Done()
			<-peer.Done()
			c.recordLoss(false)
			c.closeXSocket()
		}()
	case "hyraken-pro":
		var profile *trafficprofile.Profile
		if c.cfg.TrafficProfile != "" {
			profile = &trafficprofile.Profile{Version: 1, Timing: &trafficprofile.Timing{Enabled: true, Imprint: c.cfg.TrafficProfile, MaxDelayUS: 2000, Padding: true}}
		}
		client, err := pro.NewClient(c.ctx, pro.ClientConfig{URL: "https://" + c.cfg.Address + c.cfg.Path, Seed: string(c.cfg.Seed), TLSConfig: c.cfg.TLS, CertificatePin: c.cfg.Pin, Transport: c.cfg.Transport, Suite: c.cfg.Suite, Congestion: c.cfg.Congestion, PacketEncoding: c.cfg.PacketEncoding, Connections: 1, ElasticMux: false, Profile: profile, DialContext: c.dialPhysical, Hydra: &c.options.Hydra, HydraObserver: c.observeShaping})
		if err != nil {
			return fail("invalid_node", err)
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = client.Close()
			return fail("closed", net.ErrClosed)
		}
		c.proClient = client
		c.mu.Unlock()
		if err := client.WarmUp(ctx); err != nil {
			_ = client.Close()
			return fail("node_authentication_failed", err)
		}
	case "socks5":
		c.socksClient = socks.NewClient(&socksDialer{c}, M.ParseSocksaddr(c.cfg.Address), socks.Version5, c.cfg.Username, c.cfg.Password)
		// A real UDP_ASSOCIATE verifies SOCKS5 method/auth negotiation. Closing
		// this warm association leaves normal TCP/UDP traffic demand-driven.
		packet, err := c.socksClient.ListenPacket(ctx, M.ParseSocksaddr("0.0.0.0:0"))
		if err != nil {
			return fail("socks_udp_or_authentication_failed", err)
		}
		_ = packet.Close()
	default:
		return fail("unsupported_protocol", nil)
	}
	if err := ctx.Err(); err != nil {
		return fail("canceled", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fail("closed", net.ErrClosed)
	}
	c.ready = true
	c.hydraInstalled = c.options.Hydra.Enabled && (c.peer != nil || c.proClient != nil)
	return nil
}

func (c *Client) configureX(peer *x.Peer) error {
	if err := peer.SetHydra(c.options.Hydra); err != nil {
		return err
	}
	if err := peer.SetHydraObserver(c.observeShaping); err != nil {
		return err
	}
	target := uint64(500 * 125000)
	scenario := c.cfg.Scenario
	if scenario == "" {
		scenario = "bulk"
	}
	switch scenario {
	case "lossy":
		target = 150 * 125000
	case "speedtest":
		target = 1000 * 125000
	}
	var profile beastprofile.Profile
	if c.cfg.Mode == "beast" {
		if c.cfg.RateMbps == 0 {
			target, profile = beastprofile.HyrakenXAutoBeastProfile(target, scenario)
		} else {
			target, profile = beastprofile.FixedRateProfile(uint64(c.cfg.RateMbps)*125000, scenario)
		}
	} else {
		target, _ = beastprofile.FixedRateProfile(target, scenario)
		profile = beastprofile.HyrakenXFlashProfile(target)
	}
	peer.SetCongestionControl(beastprofile.NewWithProfile(target, peer.InitialPacketSize(), profile, false, nil))
	return nil
}

func (c *Client) reservePhysical() (func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	limit := 2
	switch c.cfg.Protocol {
	case "hyrakenx":
		limit = 1
	case "socks5":
		limit = 128
	}
	if c.closed || c.ctx.Err() != nil {
		return nil, fail("closed", net.ErrClosed)
	}
	if c.physical >= limit {
		return nil, fail("physical_limit", nil)
	}
	c.physical++
	if c.physical > c.peak {
		c.peak = c.physical
	}
	var once sync.Once
	return func() { once.Do(func() { c.mu.Lock(); c.physical--; c.mu.Unlock() }) }, nil
}
func (c *Client) control(_ string, _ string, raw syscall.RawConn) error {
	var protectErr error
	if err := raw.Control(func(fd uintptr) {
		protectErr = c.policy.Protect(int(fd))
		if protectErr == nil {
			c.mu.Lock()
			c.protected++
			c.mu.Unlock()
		}
	}); err != nil {
		return fail("socket_control_failed", err)
	}
	if protectErr != nil {
		return fail("socket_protect_failed", protectErr)
	}
	return nil
}
func (c *Client) listenX(ctx context.Context, network, address string) (net.PacketConn, error) {
	release, err := c.reservePhysical()
	if err != nil {
		return nil, err
	}
	listen := net.ListenConfig{Control: c.control}
	socket, err := listen.ListenPacket(ctx, network, address)
	if err != nil {
		release()
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = socket.Close()
		release()
		return nil, net.ErrClosed
	}
	c.xSocket = socket
	c.xRelease = release
	c.mu.Unlock()
	return socket, nil
}
func (c *Client) closeXSocket() {
	c.mu.Lock()
	socket, release := c.xSocket, c.xRelease
	c.xSocket = nil
	c.xRelease = nil
	c.mu.Unlock()
	if socket != nil {
		_ = socket.Close()
	}
	if release != nil {
		release()
	}
}

func (c *Client) dialPhysical(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fail("invalid_physical_endpoint", err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fail("invalid_physical_endpoint", err)
	}
	var addresses []netip.Addr
	configuredHost, _, _ := net.SplitHostPort(c.cfg.Address)
	if host == configuredHost {
		addresses = c.addresses
	} else if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsUnspecified() {
			addresses = c.addresses
		} else {
			addresses = []netip.Addr{ip}
		}
	} else {
		return nil, fail("unexpected_physical_endpoint", nil)
	}
	var last error
	for _, ip := range addresses {
		release, err := c.reservePhysical()
		if err != nil {
			return nil, err
		}
		dialer := net.Dialer{Timeout: 8 * time.Second, Control: c.control}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err != nil {
			release()
			last = err
			continue
		}
		owned := &physicalConn{Conn: conn, release: release, owner: c}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			_ = owned.Close()
			return nil, net.ErrClosed
		}
		c.sockets[owned] = struct{}{}
		c.mu.Unlock()
		return owned, nil
	}
	return nil, fail("physical_connect_failed", last)
}

type physicalConn struct {
	net.Conn
	owner   *Client
	release func()
	once    sync.Once
	err     error
}

func (c *physicalConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.sockets, c)
		c.owner.mu.Unlock()
		c.release()
		if c.owner.cfg.Protocol == "hyraken-pro" {
			c.owner.recordLoss(true)
		}
	})
	return c.err
}
func (c *physicalConn) SyscallConn() (syscall.RawConn, error) {
	if raw, ok := c.Conn.(syscall.Conn); ok {
		return raw.SyscallConn()
	}
	return nil, errors.New("loft.vpn.raw_socket_unavailable")
}
func (c *physicalConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.New("loft.vpn.half_close_unsupported")
}

func (c *Client) admitFlow() (func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil || !c.ready {
		return nil, fail("not_ready", nil)
	}
	if c.pendingFlows+len(c.flows)+len(c.packetFlows) >= 64 {
		return nil, fail("flow_limit", nil)
	}
	c.pendingFlows++
	c.flowWG.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.pendingFlows--
			c.mu.Unlock()
			c.flowWG.Done()
		})
	}, nil
}

func (c *Client) callContext(ctx context.Context) (context.Context, func()) {
	owned, cancel := context.WithCancel(ctx)
	stopOwner := context.AfterFunc(c.ctx, cancel)
	return owned, func() { stopOwner(); cancel() }
}

// DialTCP opens a real business byte stream.
func (c *Client) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	if ctx == nil {
		return nil, fail("invalid_context", nil)
	}
	release, err := c.admitFlow()
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	var conn net.Conn
	switch c.cfg.Protocol {
	case "hyrakenx":
		conn, err = c.peer.OpenStream(ctx, "tcp", target)
	case "hyraken-pro":
		conn, err = c.proClient.DialContext(ctx, "tcp", target)
	case "socks5":
		conn, err = c.socksClient.DialContext(ctx, "tcp", M.ParseSocksaddr(target))
	}
	if err != nil {
		return nil, fail("business_open_failed", err)
	}
	owned := &ownedConn{Conn: conn, owner: c}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return nil, fail("closed", net.ErrClosed)
	}
	c.flows[owned] = struct{}{}
	c.mu.Unlock()
	return owned, nil
}

// DialPacket opens a real datagram association.
func (c *Client) DialPacket(ctx context.Context, target string) (net.PacketConn, error) {
	if ctx == nil {
		return nil, fail("invalid_context", nil)
	}
	release, err := c.admitFlow()
	if err != nil {
		return nil, err
	}
	defer release()
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	var packet net.PacketConn
	destination := M.ParseSocksaddr(target)
	switch c.cfg.Protocol {
	case "hyrakenx":
		var conn net.Conn
		conn, err = c.peer.OpenStream(ctx, "udp", target)
		if err == nil {
			packet = x.NewStreamPacketConn(conn, destination)
		}
	case "hyraken-pro":
		network, address := "udp", target
		if c.cfg.PacketEncoding == "xudp" {
			network, address = "xudp", pro.XUDPTarget
		}
		var conn net.Conn
		conn, err = c.proClient.DialContext(ctx, network, address)
		if err == nil {
			if network == "xudp" {
				packet = pro.NewXUDPConn(conn.(pro.XUDPPacketStream))
			} else {
				packet = &fixedPacket{Conn: conn, target: destination}
			}
		}
	case "socks5":
		packet, err = c.socksClient.ListenPacket(ctx, destination)
		if err == nil {
			packet = &socksPacket{AssociatePacketConn: packet.(*socks.AssociatePacketConn), target: destination}
		}
	}
	if err != nil {
		return nil, fail("business_open_failed", err)
	}
	owned := &ownedPacket{PacketConn: packet, owner: c, min: 0, max: 65507}
	if c.cfg.Protocol == "hyrakenx" {
		owned.min, owned.max = 1, 1024
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = packet.Close()
		return nil, fail("closed", net.ErrClosed)
	}
	c.packetFlows[owned] = struct{}{}
	c.mu.Unlock()
	return owned, nil
}

// Close releases owned streams and physical sockets.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.ready = false
		peer, proClient := c.peer, c.proClient
		var streams []*ownedConn
		for stream := range c.flows {
			streams = append(streams, stream)
		}
		var packets []*ownedPacket
		for packet := range c.packetFlows {
			packets = append(packets, packet)
		}
		var sockets []net.Conn
		for socket := range c.sockets {
			sockets = append(sockets, socket)
		}
		c.mu.Unlock()
		c.cancel()
		for _, stream := range streams {
			_ = stream.Close()
		}
		for _, packet := range packets {
			_ = packet.Close()
		}
		for _, socket := range sockets {
			_ = socket.Close()
		}
		if peer != nil {
			_ = peer.Close()
		}
		if proClient != nil {
			_ = proClient.Close()
		}
		c.closeXSocket()
		// Closed/canceled fences prevent new resources, but platform resolution
		// and authentication may still be using the private configuration. Join
		// that owner before clearing its seed or confirming completion.
		c.readyMu.Lock()
		c.flowWG.Wait()
		c.monitorWG.Wait()
		clear(c.cfg.Seed)
		c.readyMu.Unlock()
	})
	return c.closeErr
}

// Stats returns redacted ownership counters.
func (c *Client) Stats() Statistics {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Statistics{PhysicalOpen: c.physical, PhysicalPeak: c.peak, ProtectedSockets: c.protected, Ready: c.ready && !c.closed && c.ctx.Err() == nil}
}

// PrivacyReady and PrivacyDone are tied to this authenticated current client.
func (c *Client) PrivacyReady() bool           { return c.Stats().Ready }
func (c *Client) PrivacyDone() <-chan struct{} { return c.ctx.Done() }

func (c *Client) PrivacyDetails() networkprivacy.TransportDetails {
	c.mu.Lock()
	applied := c.hydraInstalled && c.ready && !c.closed && c.ctx.Err() == nil
	protocol := c.cfg.Protocol
	c.mu.Unlock()
	scope := "off"
	if applied {
		if protocol == "hyrakenx" {
			scope = "logical_streams"
		} else {
			scope = "tcp_only"
		}
	}
	return networkprivacy.TransportDetails{NodeResolverCalls: c.nodeResolverCalls.Load(), HydraApplied: applied, HydraScope: scope, HydraShapedRecords: c.shapedRecords.Load(), HydraPaddingBytes: c.paddingBytes.Load()}
}

func addMetric(counter *atomic.Int64, value int64) {
	if value <= 0 {
		return
	}
	for {
		old := counter.Load()
		next := old + min(value, math.MaxInt64-old)
		if counter.CompareAndSwap(old, next) {
			return
		}
	}
}

func (c *Client) observeShaping(records, paddingBytes int) {
	addMetric(&c.shapedRecords, int64(records))
	addMetric(&c.paddingBytes, int64(paddingBytes))
}

// Lost signals an unexpected authenticated physical/protocol loss once. Normal
// policy cancellation and explicit Close do not manufacture a loss event.
func (c *Client) Lost() <-chan struct{} { return c.lost }

// LossCode returns the credential-free reason captured by the loss owner.
func (c *Client) LossCode() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lossCode
}

func (c *Client) recordLoss(requireReady bool) {
	c.mu.Lock()
	if c.closed || c.ctx.Err() != nil || c.lossCode != "" || (requireReady && !c.ready) {
		c.mu.Unlock()
		return
	}
	c.lossCode = "loft.vpn.protocol_connection_lost"
	c.ready = false
	close(c.lost)
	c.mu.Unlock()
	c.cancel()
}

type ownedConn struct {
	net.Conn
	owner *Client
	once  sync.Once
	err   error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() {
		if force, ok := c.Conn.(interface{ ForceClose() error }); ok {
			c.err = force.ForceClose()
		} else {
			c.err = c.Conn.Close()
		}
		c.owner.mu.Lock()
		delete(c.owner.flows, c)
		c.owner.mu.Unlock()
	})
	return c.err
}
func (c *ownedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.New("loft.vpn.half_close_unsupported")
}

type ownedPacket struct {
	net.PacketConn
	owner    *Client
	once     sync.Once
	err      error
	min, max int
}

func (c *ownedPacket) Close() error {
	c.once.Do(func() {
		c.err = c.PacketConn.Close()
		c.owner.mu.Lock()
		delete(c.owner.packetFlows, c)
		c.owner.mu.Unlock()
	})
	return c.err
}
func (c *ownedPacket) WriteTo(packet []byte, target net.Addr) (int, error) {
	if len(packet) < c.min || len(packet) > c.max {
		return 0, fail("udp_payload_limit", nil)
	}
	return c.PacketConn.WriteTo(packet, target)
}

type fixedPacket struct {
	net.Conn
	target net.Addr
}

// The upstream net.PacketConn bridge returns SOCKS wire byte counts and turns
// FQDN reply addresses into UDPAddr. This adapter uses its mature packet codec
// while returning application payload counts and preserving target metadata.
type socksPacket struct {
	*socks.AssociatePacketConn
	target          M.Socksaddr
	readMu, writeMu sync.Mutex
}

func (c *socksPacket) WriteTo(payload []byte, address net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	destination := M.SocksaddrFromNet(address)
	headroom := 3 + M.SocksaddrSerializer.AddrPortLen(destination)
	if len(payload)+headroom > 65507 {
		return 0, fail("udp_payload_limit", nil)
	}
	buffer := buf.NewSize(headroom + len(payload))
	buffer.Resize(headroom, 0)
	if _, err := buffer.Write(payload); err != nil {
		buffer.Release()
		return 0, err
	}
	if err := c.WritePacket(buffer, destination); err != nil {
		return 0, err
	}
	return len(payload), nil
}
func (c *socksPacket) ReadFrom(payload []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	buffer := buf.NewSize(65507)
	defer buffer.Release()
	target, err := c.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	if buffer.Len() > len(payload) {
		return 0, target, io.ErrShortBuffer
	}
	return copy(payload, buffer.Bytes()), target, nil
}

func (c *fixedPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.target, err
}
func (c *fixedPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	if a == nil || c.target == nil || a.String() != c.target.String() {
		return 0, fail("udp_target_changed", nil)
	}
	if len(b) > 65507 {
		return 0, fail("udp_payload_limit", nil)
	}
	return c.Write(b)
}

type socksDialer struct{ c *Client }

func (s *socksDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	return s.c.dialPhysical(ctx, network, address.String())
}
func (s *socksDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("loft.vpn.unsupported_direct_packet")
}

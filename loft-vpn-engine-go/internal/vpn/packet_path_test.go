//go:build with_gvisor

package vpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
	pro "loft.local/hyrakenpro"
	x "loft.local/hyrakenx"
	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
)

type memoryTUN struct {
	endpoint *channel.Endpoint
	done     chan struct{}
	once     sync.Once
}

func packetXNode(t *testing.T) *nodeconfig.Config {
	t.Helper()
	identity := testsupport.Certificates(t)
	seed := []byte("0123456789abcdef0123456789abcdef")
	listener, err := x.Listen("127.0.0.1:0", identity.ServerTLS.Clone(), seed)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = listener.Close() })
	go func() {
		peer, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		defer testsupport.Close(t, peer)
		for {
			stream, network, target, err := peer.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = stream.Close() }() // Protocol cancellation may report a cancel-close error; final runtime release is asserted.
				if network == "tcp" {
					payload, err := io.ReadAll(stream)
					if err == nil {
						_, _ = stream.Write(payload)
						_ = stream.(interface{ CloseWrite() error }).CloseWrite()
					}
					return
				}
				packet := x.NewStreamPacketConn(stream, M.ParseSocksaddr(target))
				buffer := make([]byte, 1024)
				for {
					n, address, err := packet.ReadFrom(buffer)
					if err != nil {
						return
					}
					if _, err := packet.WriteTo(buffer[:n], address); err != nil {
						return
					}
				}
			}()
		}
	}()
	return &nodeconfig.Config{Protocol: "hyrakenx", Address: listener.Addr().String(), Seed: seed, TLS: identity.ClientTLS.Clone(), Pin: identity.Pin, Mode: "flash", Scenario: "bulk"}
}

func TestActualXIPv4PacketPathTransfersTCPAndFixedTargetUDP(t *testing.T) {
	created, app := packetRigNode(t, "1.1.1.1:53", packetXNode(t))
	runtime := NewRuntime(&inertPolicy{})
	runtime.session = created
	runtime.networkPolicy = &created.networkPolicy
	runtime.generation, runtime.state = 1, "running"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	target := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 7}
	conn, err := gonet.DialContextTCP(ctx, app, target, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, conn)
	if _, err := conn.Write([]byte("X packet before FIN")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "X packet before FIN" {
		t.Fatal("X real IPv4/TCP path lost FIN or reverse bytes")
	}
	packet, err := gonet.DialUDP(app, nil, &target, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	for _, size := range []int{1, 512, 1024} {
		payload := bytes.Repeat([]byte{0x78}, size)
		_ = packet.SetDeadline(time.Now().Add(time.Second))
		// An oversized local datagram is dropped without retiring the
		// association or affecting the next valid received payload.
		if size == x.MaxDatagramPayload {
			oversized := make([]byte, x.MaxDatagramPayload+1)
			if n, err := packet.Write(oversized); err != nil || n != len(oversized) {
				t.Fatal("X oversized test datagram did not reach the local IPv4 adapter")
			}
		}
		if n, err := packet.Write(payload); err != nil || n != size {
			t.Fatal("X real IPv4 UDP write failed")
		}
		buffer := make([]byte, 1024)
		n, err := packet.Read(buffer)
		if err != nil || n != size || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("X real IPv4 UDP size %d was lost or truncated", size)
		}
	}
	if err := runtime.Stop(); err != nil {
		t.Fatal(err)
	}
	// The joined runtime must retain only the actual TCP/UDP payload totals.
	// The 19-byte TCP request, FIN and three UDP sizes make 1556 bytes/direction.
	if runtime.TrafficUsage() != "1:1:1556:1556:1" {
		t.Fatal("joined session did not report its exact application payload totals")
	}
	if err := runtime.SetNetworkPolicy(testNetworkPolicyJSON); err != nil || runtime.TrafficUsage() != "" {
		t.Fatal("installing a policy retained an earlier session's traffic")
	}
	var proof Snapshot
	created.facts(&proof)
	if !proof.ResourcesReleased || proof.ActiveFlows != 0 || proof.QueuedBytes != 0 || proof.PhysicalOpen != 0 {
		t.Fatal("X real packet stop retained owned resources")
	}
}

func TestActualXUDPAdmissionReservesItsProtocolReadLimit(t *testing.T) {
	created, _ := packetRigNode(t, "1.1.1.1:53", packetXNode(t))
	const expectedBytes = 65536 + x.MaxDatagramPayload + 512 + 4096
	for i := 0; i < 64; i++ {
		source := netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), uint16(31000+i))
		destination := netip.MustParseAddrPort("192.0.2.1:7")
		if created.JudgeFlow(17, source, destination, nil).Action != tun.ActionAccept {
			t.Fatalf("X UDP association %d hit the byte limit before the flow limit", i+1)
		}
		if used := created.budget.Used(); used != int64((i+1)*expectedBytes) {
			t.Fatalf("X UDP charged %d bytes after %d admissions, want %d", used, i+1, (i+1)*expectedBytes)
		}
	}
	if created.JudgeFlow(17, netip.MustParseAddrPort("198.18.0.1:31064"), netip.MustParseAddrPort("192.0.2.1:7"), nil).Action != tun.ActionReject {
		t.Fatal("X UDP admitted an association above the flow limit")
	}
	if err := created.stop(); err != nil || created.budget.Used() != 0 {
		t.Fatal("X pending admission stop did not release its byte owners")
	}
}

// Pro's datagram boundaries must survive actual IPv4 MTU fragmentation and
// reassembly in both directions, including zero-length and maximum payloads.
func TestActualIPv4UDPEmptyAndFragmentedPayloadsRoundTrip(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, server)
	go func() {
		buffer := make([]byte, 65507)
		for {
			n, target, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = server.WriteTo(buffer[:n], target)
		}
	}()
	_, port, _ := net.SplitHostPort(server.LocalAddr().String())
	number, _ := net.LookupPort("udp", port)
	created, app := packetRig(t, "1.1.1.1:53")
	packet, err := gonet.DialUDP(app, nil, &tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: uint16(number)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	for _, size := range []int{0, 1, 1024, 1232, 65507} {
		payload := bytes.Repeat([]byte{0x53}, size)
		_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
		if n, err := packet.Write(payload); err != nil || n != size {
			t.Fatalf("IPv4 UDP size %d write count=%d error=%v", size, n, err)
		}
		buffer := make([]byte, 65507)
		n, err := packet.Read(buffer)
		if err != nil || n != size || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("IPv4 UDP size %d read count=%d error=%v", size, n, err)
		}
	}
	if err := created.stop(); err != nil {
		t.Fatal(err)
	}
	var proof Snapshot
	created.facts(&proof)
	if !proof.ResourcesReleased || proof.QueuedBytes != 0 || proof.ActiveFlows != 0 {
		t.Fatal("UDP packet stop retained queues, flow owners, or TUN resources")
	}
}

// Android's initial IPv4-only platform scope must remain a real packet drop;
// an IPv6 application packet cannot create a hidden proxied or direct UDP flow.
func TestActualIPv6PacketsAreDroppedBeforeAnyBusinessFlow(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, server)
	_, port, _ := net.SplitHostPort(server.LocalAddr().String())
	number, _ := net.LookupPort("udp", port)
	created, app := packetRig(t, "1.1.1.1:53")
	if err := app.AddProtocolAddress(tun.DefaultNIC, tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}).WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	packet, err := gonet.DialUDP(app, nil, &tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}), Port: uint16(number)}, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	if _, err := packet.Write([]byte("IPv6 scope drop")); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := server.ReadFrom(make([]byte, 1280)); err == nil {
		t.Fatal("IPv6 application traffic reached a business destination")
	}
	var proof Snapshot
	created.facts(&proof)
	if proof.ActiveFlows != 0 || proof.QueuedBytes != 0 {
		t.Fatal("IPv6 packet bypass created a flow or memory admission")
	}
}

func (t *memoryTUN) Read([]byte) (int, error)  { return 0, io.ErrClosedPipe }
func (t *memoryTUN) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (t *memoryTUN) Name() (string, error)     { return "controlled-packet-link", nil }
func (t *memoryTUN) Start() error              { return nil }
func (t *memoryTUN) Close() error {
	t.once.Do(func() { t.endpoint.Close(); close(t.done) })
	return nil
}
func (t *memoryTUN) UpdateRouteOptions(tun.Options) error { return nil }
func (t *memoryTUN) WritePacket(packet *stack.PacketBuffer) (int, error) {
	var packets stack.PacketBufferList
	packets.PushBack(packet)
	n, err := t.endpoint.WritePackets(packets)
	if err != nil {
		return n, gonet.TranslateNetstackError(err)
	}
	return packet.Size(), nil
}
func (t *memoryTUN) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return &memoryEndpoint{LinkEndpoint: t.endpoint, done: t.done}, stack.NICOptions{}, nil
}

type memoryEndpoint struct {
	stack.LinkEndpoint
	done chan struct{}
}

func (e *memoryEndpoint) Wait() { <-e.done }

func routedNode(t *testing.T) *nodeconfig.Config {
	cfg, _ := routedNodeWithShutdown(t)
	return cfg
}

func routedNodeWithShutdown(t *testing.T) (*nodeconfig.Config, func()) {
	cfg, _, shutdown := routedNodeMaterial(t)
	return cfg, shutdown
}

func routedNodeMaterial(t *testing.T) (*nodeconfig.Config, string, func()) {
	return routedNodeMaterialObserved(t, nil)
}

func routedNodeMaterialObserved(t *testing.T, admit func(network, target string) bool) (*nodeconfig.Config, string, func()) {
	t.Helper()
	id := testsupport.Certificates(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := pro.NewServer(ctx, pro.ServerConfig{Seed: "0123456789abcdef0123456789abcdef", Path: "/hyraken.pro/Tunnel", Transport: "tcp", Suite: "chacha20-poly1305", Congestion: "beast"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })
	serverTLS := id.ServerTLS.Clone()
	serverTLS.ClientAuth = tls.NoClientCert
	serverTLS.ClientCAs = nil
	go func() { _ = server.Serve(listener, serverTLS) }()
	go func() {
		for {
			stream, err := server.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = stream.Close() }() // Protocol cancellation may report a cancel-close error; final runtime release is asserted.
				if admit != nil && !admit(stream.Network(), stream.Target()) {
					return
				}
				_, port, err := net.SplitHostPort(stream.Target())
				if err != nil {
					return
				}
				remote, err := net.DialTimeout(stream.Network(), net.JoinHostPort("127.0.0.1", port), time.Second)
				if err != nil {
					return
				}
				defer testsupport.Close(t, remote)
				if stream.Network() == "tcp" {
					result := make(chan struct{}, 1)
					go func() {
						_, _ = io.Copy(remote, stream)
						if half, ok := remote.(interface{ CloseWrite() error }); ok {
							_ = half.CloseWrite()
						}
						result <- struct{}{}
					}()
					_, _ = io.Copy(stream, remote)
					<-result
				} else {
					buffer := make([]byte, 65507)
					for {
						n, err := stream.Read(buffer)
						if err != nil {
							return
						}
						if _, err = remote.Write(buffer[:n]); err != nil {
							return
						}
						n, err = remote.Read(buffer)
						if err != nil {
							return
						}
						if _, err = stream.Write(buffer[:n]); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	clientTLS := id.ClientTLS.Clone()
	clientTLS.Certificates = nil
	cfg := &nodeconfig.Config{Protocol: "hyraken-pro", Address: listener.Addr().String(), Seed: []byte("0123456789abcdef0123456789abcdef"), TLS: clientTLS, Pin: id.Pin, Path: "/hyraken.pro/Tunnel", Transport: "tcp", Suite: "chacha20-poly1305", Congestion: "beast", Connections: 1}
	query := url.Values{"sni": {"node.test"}, "pin": {id.Pin}, "certificate": {base64.StdEncoding.EncodeToString(id.Server)}, "path": {cfg.Path}, "transport": {"tcp"}, "suite": {cfg.Suite}, "congestion": {cfg.Congestion}}
	raw := "hyraken-pro://0123456789abcdef0123456789abcdef@" + cfg.Address + "?" + query.Encode()
	return cfg, raw, func() { _ = server.Close(); _ = listener.Close(); cancel() }
}

// A real authenticated peer loss reaches the session listener and disables
// forwarding while preserving Go's TUN ownership until an actual Stop.
func TestProtocolLossDisablesForwardingAndPublishesCapturedLoss(t *testing.T) {
	cfg, shutdown := routedNodeWithShutdown(t)
	device := &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}
	options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, MTU: 1280, DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
	lost := make(chan string, 1)
	created, err := startWithTun(context.Background(), device, options, cfg, &inertPolicy{}, testWirePolicy(t, "1.1.1.1:53"), func(code string) { lost <- code })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = created.stop() }() // Fallback cleanup; the test checks the stop receipt explicitly.
	shutdown()
	select {
	case code := <-lost:
		if code != "loft.vpn.protocol_connection_lost" {
			t.Fatal("peer loss published an unrelated or unsafe error")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("unexpected authenticated protocol loss did not reach the state listener")
	}
	snapshot := Snapshot{State: "running"}
	created.facts(&snapshot)
	if snapshot.TransportReady || snapshot.Authenticated || !snapshot.ForwardingDisabled || !snapshot.TunOwned || snapshot.ResourcesReleased {
		t.Fatal("peer loss left forwarding ready or fabricated TUN/resource release")
	}
	if err := created.stop(); err != nil {
		t.Fatal(err)
	}
	created.facts(&snapshot)
	if !snapshot.ResourcesReleased {
		t.Fatal("real stop after loss did not release session owners")
	}
}

func packetRig(t *testing.T, dns string) (*session, *stack.Stack) {
	return packetRigNode(t, dns, routedNode(t))
}

func packetRigNode(t *testing.T, dns string, cfg *nodeconfig.Config) (*session, *stack.Stack) {
	return packetRigNodeWithPolicy(t, testWirePolicy(t, dns), cfg)
}

func packetRigNodeWithPolicy(t *testing.T, networkPolicy networkprivacy.Policy, cfg *nodeconfig.Config) (*session, *stack.Stack) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	device := &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}
	options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, MTU: 1280, DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
	created, err := startWithTun(ctx, device, options, cfg, &inertPolicy{}, networkPolicy, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = created.stop() })
	return created, attachPacketApp(t, device, ctx)
}

func attachPacketApp(t *testing.T, device *memoryTUN, ctx context.Context) *stack.Stack {
	t.Helper()
	appEndpoint := channel.New(64, 1280, "")
	app, err := tun.NewGVisorStackWithMobileLimits(appEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	if err := app.AddProtocolAddress(tun.DefaultNIC, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{198, 18, 0, 1}).WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			packet := appEndpoint.ReadContext(ctx)
			if packet == nil {
				return
			}
			fresh := wirePacket(packet)
			device.endpoint.InjectInbound(packet.NetworkProtocolNumber, fresh)
			fresh.DecRef()
			packet.DecRef()
		}
	}()
	go func() {
		for {
			packet := device.endpoint.ReadContext(ctx)
			if packet == nil {
				return
			}
			fresh := wirePacket(packet)
			appEndpoint.InjectInbound(packet.NetworkProtocolNumber, fresh)
			fresh.DecRef()
			packet.DecRef()
		}
	}()
	return app
}

// SOCKS uses the same real IPv4 packet/TCP/UDP stack, with demand-driven protected
// sockets. Its UDP payload bound also includes the standard SOCKS envelope.
func TestActualSocksIPv4PacketPathPreservesTCPFINAndUDPDatagrams(t *testing.T) {
	address := testsupport.SocksServer(t, "synthetic-user", "synthetic-password")
	created, app := packetRigNode(t, "1.1.1.1:53", &nodeconfig.Config{Protocol: "socks5", Address: address, Username: "synthetic-user", Password: "synthetic-password"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 7}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, conn)
	if _, err := conn.Write([]byte("SOCKS packet before FIN")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "SOCKS packet before FIN" {
		t.Fatal("real SOCKS packet path lost TCP FIN or reverse bytes")
	}
	packet, err := gonet.DialUDP(app, nil, &tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 7}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	for _, size := range []int{0, 1, 1024, 65000} {
		payload := bytes.Repeat([]byte{0x73}, size)
		_ = packet.SetDeadline(time.Now().Add(time.Second))
		if n, err := packet.Write(payload); err != nil || n != size {
			t.Fatal("SOCKS IPv4 UDP write failed")
		}
		buffer := make([]byte, 65507)
		n, err := packet.Read(buffer)
		if err != nil || n != size || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("SOCKS IPv4 UDP payload size %d was lost or truncated", size)
		}
	}
	if err := created.stop(); err != nil {
		t.Fatal(err)
	}
	var proof Snapshot
	created.facts(&proof)
	if !proof.ResourcesReleased || proof.ActiveFlows != 0 || proof.QueuedBytes != 0 || proof.PhysicalOpen != 0 {
		t.Fatal("SOCKS real packet stop retained physical, flow or byte owners")
	}
}

func wirePacket(packet *stack.PacketBuffer) *stack.PacketBuffer {
	var wire []byte
	for _, part := range packet.AsSlices() {
		wire = append(wire, part...)
	}
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
}

func rawSYN(sourcePort, targetPort uint16) *stack.PacketBuffer {
	wire := make([]byte, 40)
	source := tcpip.AddrFrom4([4]byte{198, 18, 0, 1})
	destination := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	ip := header.IPv4(wire[:20])
	ip.Encode(&header.IPv4Fields{TotalLength: 40, TTL: 64, Protocol: uint8(header.TCPProtocolNumber), SrcAddr: source, DstAddr: destination})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(wire[20:])
	tcp.Encode(&header.TCPFields{SrcPort: sourcePort, DstPort: targetPort, SeqNum: 1, DataOffset: 20, Flags: header.TCPFlagSyn, WindowSize: 4096})
	tcp.SetChecksum(^tcp.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, source, destination, 20)))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
}

// Half-open client handshakes are real gVisor endpoints. Abort must interrupt
// their handshake wait, freeze the 65th flow, and retain the TUN until Stop.
func TestActualSYNFloodAdmissionAndAbortJoinPendingTCPHandshakes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer testsupport.Close(t, conn); _, _ = io.Copy(io.Discard, conn) }()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := net.LookupPort("tcp", port)
	device := &memoryTUN{endpoint: channel.New(128, 1280, ""), done: make(chan struct{})}
	r := runningRuntime(t, device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			packet := device.endpoint.ReadContext(ctx)
			if packet == nil {
				return
			}
			packet.DecRef()
		}
	}()
	for i := 0; i < 65; i++ {
		packet := rawSYN(uint16(30000+i), uint16(number))
		device.endpoint.InjectInbound(header.IPv4ProtocolNumber, packet)
		packet.DecRef()
	}
	deadline := time.Now().Add(time.Second)
	for r.Snapshot().ActiveFlows != 64 {
		if time.Now().After(deadline) {
			t.Fatal("real SYN admission did not establish exactly 64 pending owners")
		}
		time.Sleep(time.Millisecond)
	}
	if snapshot := r.Snapshot(); snapshot.ActiveFlows != 64 || snapshot.QueuedBytes > 8388608 {
		t.Fatal("65th SYN exceeded flow or added byte admission")
	}
	result := make(chan error, 1)
	go func() { result <- r.Abort() }()
	blocked := false
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		blocked = true
		// Release the actual netstack endpoint workers for regression cleanup;
		// this is the owned resource that the production Abort must interrupt.
		_ = r.session.stack.Close()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("pending handshake remained blocked after netstack teardown")
		}
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Fatal("Abort could not interrupt real half-open TCP handshake workers")
	}
	if snapshot := r.Snapshot(); !snapshot.ResourcesReleased || snapshot.ActiveFlows != 0 || snapshot.QueuedBytes != 0 {
		t.Fatal("SYN flood stop retained admitted owners or bytes")
	}
}

// Actual IPv4 packets traverse gVisor TCP -> protected/authenticated Pro -> a
// controlled real TCP service. This is host packet-stack evidence, not Android.
func TestActualIPPacketPathTransfersTCPAndPreservesHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer testsupport.Close(t, conn)
		payload, err := io.ReadAll(conn)
		if err == nil && string(payload) == "request before FIN" {
			_, _ = conn.Write([]byte("late reverse bytes"))
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := net.LookupPort("tcp", port)
	created, app := packetRig(t, "1.1.1.1:53")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: uint16(number)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, conn)
	if _, err := conn.Write([]byte("request before FIN")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "late reverse bytes" {
		t.Fatal("real IP/TCP half-close lost remote EOF or late reverse data")
	}
	if err := created.stop(); err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{State: "stopped"}
	created.facts(&snapshot)
	if !snapshot.ResourcesReleased || !snapshot.ForwardingDisabled || snapshot.PhysicalOpen != 0 || snapshot.TunOwned {
		t.Fatal("stop receipt retained owned packet-stack resources")
	}
}

// Drain must retain an existing real packet flow through its FIN and late
// reverse data while freezing any new SYN admission, then keep the TUN for Stop.
func TestActualPacketDrainPreservesExistingHalfCloseAndFreezesNewAdmission(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer testsupport.Close(t, conn)
		payload, err := io.ReadAll(conn)
		if err == nil && string(payload) == "drain through FIN" {
			_, _ = conn.Write([]byte("drained reverse bytes"))
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := net.LookupPort("tcp", port)
	created, app := packetRig(t, "1.1.1.1:53")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	target := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: uint16(number)}
	conn, err := gonet.DialContextTCP(ctx, app, target, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, conn)
	if _, err := conn.Write([]byte("drain through FIN")); err != nil {
		t.Fatal(err)
	}
	drained := make(chan error, 1)
	go func() { drained <- created.drain(2 * time.Second) }()
	deadline := time.Now().Add(time.Second)
	for {
		created.mu.Lock()
		admissionFrozen := !created.enabled
		created.mu.Unlock()
		if admissionFrozen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Drain did not freeze actual packet admission")
		}
		time.Sleep(time.Millisecond)
	}
	rejected, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	if fresh, err := gonet.DialContextTCP(rejected, app, target, ipv4.ProtocolNumber); err == nil {
		_ = fresh.Close()
		stop()
		t.Fatal("draining packet stack admitted a new TCP flow")
	}
	stop()
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "drained reverse bytes" {
		t.Fatal("Drain cut off existing FIN or late reverse data")
	}
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Drain did not join its completed packet flow")
	}
	proof := Snapshot{State: "blocked"}
	created.facts(&proof)
	if !proof.TunOwned || proof.ResourcesReleased || !proof.ForwardingDisabled || proof.QueuedBytes != 0 || proof.TransportReady {
		t.Fatal("Drain fabricated TUN release or retained forwarding owners")
	}
	if err := created.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestActualPacketDrainDeadlineAbortsLiveFlowAndStopJoins(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer testsupport.Close(t, conn)
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := net.LookupPort("tcp", port)
	created, app := packetRig(t, "1.1.1.1:53")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: uint16(number)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, conn)
	if err := created.drain(time.Millisecond); errorCode(err) != "loft.vpn.drain_timeout" {
		t.Fatal("live packet drain did not return its deadline failure")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("drain deadline failed to wake a live application reader")
	}
	if err := created.stop(); err != nil {
		t.Fatal(err)
	}
	var proof Snapshot
	created.facts(&proof)
	if !proof.ResourcesReleased || !proof.ForwardingDisabled || proof.QueuedBytes != 0 || proof.ActiveFlows != 0 {
		t.Fatal("live packet deadline left unjoined flow, TUN or byte owners")
	}
}

// Synthetic UDP DNS is converted to TCP framing inside the same proxy; no host
// DNS query or direct resolver supplies the application answer.
func TestSyntheticDNSPacketsUseTunneledTCPFraming(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer testsupport.Close(t, conn)
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		wire := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(conn, wire); err != nil {
			return
		}
		var message dnsmessage.Message
		if message.Unpack(wire) != nil || len(message.Questions) != 1 {
			return
		}
		message.Response = true
		message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 2}}}}
		response, err := message.Pack()
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(prefix[:], uint16(len(response)))
		_ = writeAll(conn, append(prefix[:], response...))
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	_, app := packetRig(t, net.JoinHostPort("192.0.2.1", port))
	packet, err := gonet.DialUDP(app, nil, &tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	name, _ := dnsmessage.NewName("packet.test.")
	query, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := packet.Write(query); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	n, err := packet.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var reply dnsmessage.Message
	if reply.Unpack(buffer[:n]) != nil || reply.ID != 1234 || reply.RCode != dnsmessage.RCodeSuccess || len(reply.Answers) != 1 {
		t.Fatal("synthetic DNS did not return the tunneled TCP server answer")
	}
}

// A DNS owner retains both its copied query and TCP-framed query while waiting
// for the response. The global byte ledger must include both real allocations.
func TestTunneledDNSByteReservationIncludesQueryAndWireCopy(t *testing.T) {
	name := dnsmessage.MustNewName(strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + ".")
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Additionals: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: make([]byte, 1020)}}}}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	received := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer testsupport.Close(t, conn)
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil || int(binary.BigEndian.Uint16(length[:])) != len(query) {
			return
		}
		framed := make([]byte, len(query))
		if _, err := io.ReadFull(conn, framed); err != nil || !bytes.Equal(framed, query) {
			return
		}
		close(received)
		_, _ = io.Copy(io.Discard, conn)
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	created, app := packetRig(t, net.JoinHostPort("192.0.2.1", port))
	packet, err := gonet.DialUDP(app, nil, &tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	if _, err := packet.Write(query); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("actual tunneled DNS did not write its complete framed query")
	}
	reserved := created.budget.Used()
	if err := created.stop(); err != nil {
		t.Fatal(err)
	}
	if reserved < int64(2*len(query)+65535) {
		t.Fatal("DNS byte reservation omitted its live framed-query allocation")
	}
}

//go:build with_gvisor

package vpn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"golang.org/x/net/dns/dnsmessage"
	"net.aptist.loft/loft-vpn-engine-go/internal/networkprivacy"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
)

func syntheticQuery(t *testing.T, app *stack.Stack, tcp bool, name string, typ dnsmessage.Type, dnssec bool) dnsmessage.Message {
	t.Helper()
	question, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 77, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: question, Type: typ, Class: dnsmessage.ClassINET}}, Additionals: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{}}}}
	if dnssec {
		message.Additionals[0].Header.TTL = 0x8000
	}
	query, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	target := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{198, 18, 0, 2}), Port: 53}
	var response []byte
	if tcp {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := gonet.DialContextTCP(ctx, app, target, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer testsupport.Close(t, conn)
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		wire := make([]byte, len(query)+2)
		binary.BigEndian.PutUint16(wire, uint16(len(query)))
		copy(wire[2:], query)
		if err := writeAll(conn, wire); err != nil {
			t.Fatal(err)
		}
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			t.Fatal(err)
		}
		size := int(binary.BigEndian.Uint16(prefix[:]))
		if size < 12 || size > 4096 {
			t.Fatal("invalid synthetic TCP response bound")
		}
		response = make([]byte, size)
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatal(err)
		}
	} else {
		conn, err := gonet.DialUDP(app, nil, &target, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		defer testsupport.Close(t, conn)
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(query); err != nil {
			t.Fatal(err)
		}
		response = make([]byte, 4096)
		n, err := conn.Read(response)
		if err != nil {
			t.Fatal(err)
		}
		response = response[:n]
	}
	var answer dnsmessage.Message
	if err := answer.Unpack(response); err != nil {
		t.Fatal(err)
	}
	if !answer.Response || answer.ID != message.ID {
		t.Fatal("DNS reply lacks original query identity")
	}
	return answer
}

func TestActualSyntheticDNSRestoresFQDNForVerifiedTLSAndUDP(t *testing.T) {
	for _, kind := range []string{"X", "Pro", "SOCKS"} {
		t.Run(kind, func(t *testing.T) { exerciseSyntheticPacketPath(t, kind) })
	}
}

func exerciseSyntheticPacketPath(t *testing.T, kind string) {
	opens := make(chan string, 8)
	admit := func(network, target string) bool {
		host, _, err := net.SplitHostPort(target)
		if err != nil || host != "node.test" {
			return false
		}
		select {
		case opens <- network + ":" + target:
		default:
			return false
		}
		return true
	}
	var cfg *nodeconfig.Config
	switch kind {
	case "X":
		cfg = privacyXNode(t, admit)
	case "Pro":
		cfg, _, _ = routedNodeMaterialObserved(t, admit)
	case "SOCKS":
		cfg = privacySocksNode(t, admit)
	}
	policy := testPrivacyPolicy(t, nil)
	created, app := packetRigNodeWithPolicy(t, policy, cfg)
	proof := Snapshot{State: "running"}
	created.facts(&proof)
	if !proof.EnforcementActive || !proof.DNSProtectionEnforced || !proof.WebRTCProtectionEnforced || !proof.IPv6DropActive || proof.DNSAllocatorBytes != 540672 || proof.BusinessResolverCalls != 0 {
		t.Fatal("actual authenticated/installed packet path did not publish matching privacy proof")
	}
	var address netip.Addr
	for _, tcp := range []bool{false, true} {
		answer := syntheticQuery(t, app, tcp, "node.test.", dnsmessage.TypeA, false)
		if answer.RCode != dnsmessage.RCodeSuccess || len(answer.Answers) != 1 {
			t.Fatal("default fake-IP DNS returned no routing alias")
		}
		record, ok := answer.Answers[0].Body.(*dnsmessage.AResource)
		if !ok || answer.Answers[0].Header.TTL != 60 {
			t.Fatal("synthetic answer lost its bounded TTL/type")
		}
		ip := netip.AddrFrom4(record.A)
		if !networkprivacy.FakePrefix().Contains(ip) || address.IsValid() && ip != address {
			t.Fatal("DNS modes changed the canonical domain alias")
		}
		address = ip
	}
	select {
	case <-opens:
		t.Fatal("synthetic DNS opened an external resolver stream")
	default:
	}
	identity := testsupport.Certificates(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := identity.ServerTLS.Clone()
	serverTLS.ClientAuth = tls.NoClientCert
	serverTLS.ClientCAs = nil
	server := &http.Server{ReadHeaderTimeout: 2 * time.Second, Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "node.test" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = writer.Write([]byte("verified FQDN"))
	})}
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })
	go func() { _ = server.Serve(tls.NewListener(listener, serverTLS)) }()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4(address.As4()), Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	secured := tls.Client(conn, identity.ClientTLS.Clone())
	defer func() { _ = secured.Close() }() // Explicit Stop may already have closed TLS; actual active-resource joins are asserted below.
	_ = secured.SetDeadline(time.Now().Add(3 * time.Second))
	if err := secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(secured, "GET / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secured), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "verified FQDN" || len(secured.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("returned alias did not route genuine hostname/certificate/HTTP data")
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, udp)
	go func() {
		data := make([]byte, 65507)
		for {
			n, target, err := udp.ReadFrom(data)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(data[:n], target)
		}
	}()
	udpPort := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	packet, err := gonet.DialUDP(app, nil, &tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4(address.As4()), Port: udpPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	sizes := []int{0, 1, 1232, 65507}
	if kind == "X" {
		sizes = []int{1, 512, 1024}
	}
	if kind == "SOCKS" {
		sizes = []int{0, 1, 1232, 65491}
	}
	for _, size := range sizes {
		payload := bytes.Repeat([]byte{0x52}, size)
		_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
		if n, err := packet.Write(payload); err != nil || n != size {
			t.Fatalf("mapped UDP %d write failed", size)
		}
		reply := make([]byte, 65507)
		n, err := packet.Read(reply)
		if err != nil || n != size || !bytes.Equal(reply[:n], payload) {
			t.Fatalf("mapped UDP %d reply lost alias/boundary/empty semantics", size)
		}
	}
	created.facts(&proof)
	if proof.DNSSyntheticCount != 2 || proof.DNSValidatedWireCount != 0 || proof.NodeResolverCalls != 0 || proof.BusinessResolverCalls != 0 || proof.DNSMapEntries != 1 || proof.DNSMapBytes != 1024 {
		t.Fatal("synthetic routing confused DNS outcomes, node bootstrap or retained map resources")
	}
	if err := created.stop(); err != nil {
		t.Fatal(err)
	}
	created.facts(&proof)
	if proof.EnforcementActive || proof.DNSProtectionEnforced || proof.WebRTCProtectionEnforced || proof.IPv6DropActive || !proof.ResourcesReleased || proof.QueuedBytes != 0 || proof.DNSMapBytes != 0 || proof.DNSMapEntries != 0 || proof.DNSAllocatorBytes != 540672 {
		t.Fatal("Stop retained active proof/resources or falsely discarded fixed quarantine metadata")
	}
}

func TestActualRuntimeStopRetainsFinalScopedCountersAndNextPolicyResets(t *testing.T) {
	_, raw, _ := routedNodeMaterial(t)
	raw = strings.Replace(raw, "127.0.0.1:", "node.invalid:", 1)
	r := NewRuntime(&inertPolicy{})
	defer func() { _ = r.Close() }()
	hydraFields := map[string]any{"enabled": true, "auto_jitter": true, "rotation_seconds": 300, "rotation_jitter_percent": 0, "chunk_min_percent": 0, "burst_min_records": 0, "burst_max_records": 0, "padding_gap_max_records": 1}
	if err := r.SetNetworkPolicy(testPolicyJSON(t, map[string]any{"hydra": hydraFields})); err != nil {
		t.Fatal(err)
	}
	device := &memoryTUN{endpoint: channel.New(64, 1280, ""), done: make(chan struct{})}
	create := func(ctx context.Context, cfg *nodeconfig.Config, address netip.Prefix, mtu int, policy networkprivacy.Policy, lost func(string)) (*session, error) {
		options := tun.Options{Name: "controlled-packet-link", Inet4Address: []netip.Prefix{address}, MTU: uint32(mtu), DNSMode: tun.DNSModeDisabled, EXP_DisableDNSHijack: true}
		return startWithTun(ctx, device, options, cfg, r.policy, policy, lost)
	}
	if err := r.start(raw, "198.18.0.1/30", 1280, create); err != nil {
		t.Fatal(err)
	}
	app := attachPacketApp(t, device, r.session.ctx)
	answer := syntheticQuery(t, app, false, "node.test.", dnsmessage.TypeA, false)
	address := netip.AddrFrom4(answer.Answers[0].Body.(*dnsmessage.AResource).A)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		payload, err := io.ReadAll(conn)
		if err == nil {
			_, _ = conn.Write(payload)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4(address.As4()), Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, conn)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0x64}, 16384)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(reply, payload) {
		t.Fatal("actual runtime shaped stream did not preserve EOF/application bytes")
	}
	before := r.Snapshot()
	if before.DNSSyntheticCount != 1 || before.DNSValidatedWireCount != 0 || before.NodeResolverCalls != 1 || before.BusinessResolverCalls != 0 || before.HydraShapedRecords == 0 || !before.EnforcementActive || !before.HydraApplied {
		t.Fatal("actual runtime never recorded scoped DNS/bootstrap/shaped data")
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	final := r.Snapshot()
	if final.PolicyEpoch != before.PolicyEpoch || final.ScopeID != before.ScopeID || final.DNSSyntheticCount != before.DNSSyntheticCount || final.DNSValidatedWireCount != before.DNSValidatedWireCount || final.NodeResolverCalls != before.NodeResolverCalls || final.HydraShapedRecords != before.HydraShapedRecords || final.HydraPaddingBytes != before.HydraPaddingBytes {
		t.Fatal("joined Runtime.Stop discarded or rebound actual final scope counters")
	}
	if final.EnforcementActive || final.DNSProtectionEnforced || final.WebRTCProtectionEnforced || final.IPv6DropActive || final.HydraApplied || final.HydraScope != "off" || final.TransportReady || final.DNSMapEntries != 0 || final.DNSMapBytes != 0 || final.ActiveFlows != 0 || final.QueuedBytes != 0 || final.PhysicalOpen != 0 || final.OwnershipPending || !final.ResourcesReleased {
		t.Fatal("final totals restored active proof or hid remaining runtime ownership")
	}
	if err := r.SetNetworkPolicy(testPolicyJSON(t, map[string]any{"policy_epoch": "2", "scope_id": strings.Repeat("b", 64)})); err != nil {
		t.Fatal(err)
	}
	next := r.Snapshot()
	if next.PolicyEpoch != "2" || next.ScopeID != strings.Repeat("b", 64) || next.DNSSyntheticCount != 0 || next.NodeResolverCalls != 0 || next.HydraShapedRecords != 0 || next.HydraPaddingBytes != 0 || next.EnforcementActive || next.DNSAllocatorBytes != 540672 {
		t.Fatal("new idle policy inherited prior-scope totals/proof or lost fixed metadata accounting")
	}
}

func TestActualBlockPolicyRetainsLateSTUNIdentityForEmptyUDP(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, server)
	var received atomic.Int64
	go func() {
		data := make([]byte, 65507)
		for {
			n, target, err := server.ReadFrom(data)
			if err != nil {
				return
			}
			received.Add(1)
			_, _ = server.WriteTo(data[:n], target)
		}
	}()
	created, app := packetRigNodeWithPolicy(t, testPrivacyPolicy(t, map[string]any{"webrtc_policy": "block"}), routedNode(t))
	target := tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: uint16(server.LocalAddr().(*net.UDPAddr).Port)}
	packet, err := gonet.DialUDP(app, nil, &target, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	ordinary := make([]byte, 20)
	binary.BigEndian.PutUint16(ordinary, 1)
	binary.BigEndian.PutUint32(ordinary[4:], 0x2112a443)
	_ = packet.SetDeadline(time.Now().Add(time.Second))
	if _, err := packet.Write(ordinary); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 65507)
	if n, err := packet.Read(reply); err != nil || !bytes.Equal(reply[:n], ordinary) {
		t.Fatal("cookie-invalid ordinary UDP was wrongly denied")
	}
	stun := append([]byte(nil), ordinary...)
	binary.BigEndian.PutUint32(stun[4:], 0x2112a442)
	if _, err := packet.Write(stun); err != nil {
		t.Fatal(err)
	}
	_ = packet.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := packet.Read(reply); err == nil {
		t.Fatal("classified STUN reached the actual destination")
	}
	if _, err := packet.Write(nil); err != nil {
		t.Fatal(err)
	}
	_ = packet.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := packet.Read(reply); err == nil {
		t.Fatal("empty UDP forgot the blocked association's STUN identity")
	}
	proof := Snapshot{State: "running"}
	created.facts(&proof)
	if received.Load() != 1 || proof.WebRTCClassifiedCount == 0 || proof.WebRTCPolicyDropCount == 0 || !proof.EnforcementActive {
		t.Fatal("actual UDP denial confused ordinary/classified/current-source evidence")
	}
}

func TestActualFragmentedTCPSTUNBlockPreventsEveryProhibitedByte(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	_, app := packetRigNodeWithPolicy(t, testPrivacyPolicy(t, map[string]any{"webrtc_policy": "block", "dns_leak_policy": "block"}), routedNode(t))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, app, tcpip.FullAddress{NIC: tun.DefaultNIC, Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, conn)
	var remote net.Conn
	select {
	case remote = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("actual guarded TCP did not open its controlled target")
	}
	defer testsupport.Close(t, remote)
	stun := make([]byte, 20)
	binary.BigEndian.PutUint16(stun, 1)
	binary.BigEndian.PutUint32(stun[4:], 0x2112a442)
	if _, err := conn.Write(stun[:2]); err != nil {
		t.Fatal(err)
	}
	_ = remote.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _ := remote.Read(make([]byte, 32)); n != 0 {
		t.Fatal("undecided fragmented STUN prefix reached the target")
	}
	if _, err := conn.Write(stun[2:]); err != nil {
		t.Fatal(err)
	}
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if n, _ := remote.Read(make([]byte, 32)); n != 0 {
		t.Fatal("identified fragmented STUN bytes reached the target")
	}
}

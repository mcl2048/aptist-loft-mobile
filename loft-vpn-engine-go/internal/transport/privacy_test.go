package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"loft.local/hydra"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
)

func TestSelectedTransportPrivacyProofAndActualHydraRecords(t *testing.T) {
	for _, kind := range []struct{ name, protocol, carrier, scope string }{
		{"X", "hyrakenx", "", "logical_streams"},
		{"ProTCP", "hyraken-pro", "tcp", "tcp_only"},
		{"ProGRPC", "hyraken-pro", "grpc", "tcp_only"},
	} {
		for _, enabled := range []bool{false, true} {
			name := kind.name + "/disabled"
			if enabled {
				name = kind.name + "/enabled"
			}
			t.Run(name, func(t *testing.T) {
				cfg := fixtureNode(t, kind.protocol, kind.carrier, false)
				platform := &observedPolicy{}
				client, err := NewClientWithOptions(context.Background(), cfg, platform, ClientOptions{Hydra: hydra.Config{Enabled: enabled, RotationSeconds: 300}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = client.Close() }()
				if client.PrivacyReady() || client.PrivacyDetails().HydraApplied || platform.count.Load() != 0 {
					t.Fatal("construction manufactured privacy/shaping or I/O")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				if err := client.Ready(ctx); err != nil {
					t.Fatal(err)
				}
				details := client.PrivacyDetails()
				if !client.PrivacyReady() || details.HydraApplied != enabled || details.HydraShapedRecords != 0 || details.NodeResolverCalls != 0 || details.BusinessResolverCalls != 0 {
					t.Fatal("authentication confused requested/applied/shaped or resolver facts")
				}
				if enabled && details.HydraScope != kind.scope || !enabled && details.HydraScope != "off" {
					t.Fatal("actual shaping scope is incorrect")
				}
				conn, err := client.DialTCP(ctx, "echo.test:7")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				payload := bytes.Repeat([]byte{0x31}, 16384)
				reply := make([]byte, len(payload))
				for i := 0; i < 8; i++ {
					if n, err := conn.Write(payload); err != nil || n != len(payload) {
						t.Fatalf("shaped stream write failed: n=%d err=%v", n, err)
					}
					if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(payload, reply) {
						t.Fatal("record shaping changed authenticated application bytes")
					}
				}
				details = client.PrivacyDetails()
				if enabled && details.HydraShapedRecords == 0 || !enabled && (details.HydraShapedRecords != 0 || details.HydraPaddingBytes != 0) {
					t.Fatalf("shaping counters lack actual submitted-record evidence: records=%d padding=%d", details.HydraShapedRecords, details.HydraPaddingBytes)
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-client.PrivacyDone():
				default:
					t.Fatal("Close did not revoke the selected privacy source")
				}
				if client.PrivacyReady() || client.PrivacyDetails().HydraApplied || client.Stats().PhysicalOpen != 0 {
					t.Fatal("closed adapter retained proof or physical ownership")
				}
			})
		}
	}
}

func TestAdaptiveHydraReportsActualPaddingAfterSuccessfulWrites(t *testing.T) {
	for _, protocol := range []string{"hyrakenx", "hyraken-pro"} {
		t.Run(protocol, func(t *testing.T) {
			cfg := fixtureNode(t, protocol, "tcp", false)
			client, err := NewClientWithOptions(context.Background(), cfg, &observedPolicy{}, ClientOptions{Hydra: hydra.Config{Enabled: true, AutoJitter: true, PaddingGapMaxRecords: 1}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := client.Ready(ctx); err != nil {
				t.Fatal(err)
			}
			conn, err := client.DialTCP(ctx, "echo.test:7")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{0x47}, 16384)
			reply := make([]byte, len(payload))
			for i := 0; i < 128 && client.PrivacyDetails().HydraPaddingBytes == 0; i++ {
				if n, err := conn.Write(payload); err != nil || n != len(payload) {
					t.Fatal("adaptive record write failed")
				}
				if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(payload, reply) {
					t.Fatal("adaptive padding entered application reads")
				}
			}
			if details := client.PrivacyDetails(); details.HydraPaddingBytes == 0 || details.HydraShapedRecords == 0 {
				t.Fatal("adaptive record/padding observations remained empty after bounded actual traffic")
			}
		})
	}
}

type domainNodePolicy struct{ observedPolicy }

func (p *domainNodePolicy) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	if name != "node.invalid" {
		return nil, io.ErrUnexpectedEOF
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ctx.Err()
}

func TestOnlyDomainNodeBootstrapUsesThePhysicalResolver(t *testing.T) {
	cfg := fixtureNode(t, "hyraken-pro", "tcp", false)
	_, port, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Address = net.JoinHostPort("node.invalid", port)
	client, err := NewClientWithOptions(context.Background(), cfg, &domainNodePolicy{}, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialTCP(ctx, "business.invalid:7")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if facts := client.PrivacyDetails(); facts.NodeResolverCalls != 1 || facts.BusinessResolverCalls != 0 {
		t.Fatal("business domain used the node's physical resolver callback")
	}
}

func TestSOCKSHydraRequestIsUnsupportedBeforeNetworking(t *testing.T) {
	platform := &observedPolicy{}
	if _, err := NewClientWithOptions(context.Background(), &nodeconfig.Config{Protocol: "socks5", Address: "127.0.0.1:1080"}, platform, ClientOptions{Hydra: hydra.Config{Enabled: true}}); err == nil || err.Error() != "loft.vpn.hydra_unsupported_transport" || platform.count.Load() != 0 {
		t.Fatal("unsupported SOCKS shaping created a protocol owner or network call")
	}
}

func TestIPv6LiteralNodeRemainsUnsupportedBeforeAnyPlatformNetworkCall(t *testing.T) {
	platform := &observedPolicy{}
	client, err := NewClient(context.Background(), &nodeconfig.Config{Protocol: "socks5", Address: "[::1]:1080"}, platform)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Ready(ctx); err == nil || err.Error() != "loft.vpn.ipv6_unavailable" || platform.count.Load() != 0 || client.PrivacyReady() {
		t.Fatal("literal-node resolver bypass admitted unsupported IPv6 physical networking")
	}
}

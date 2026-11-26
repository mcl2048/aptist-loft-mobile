package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	pro "loft.local/hyrakenpro"
	x "loft.local/hyrakenx"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
)

type observedPolicy struct {
	count  atomic.Int32
	reject bool
}

// A wrapper without half-close support must not return a fake successful FIN.
func TestUnsupportedHalfCloseReturnsExplicitFailure(t *testing.T) {
	left, right := net.Pipe()
	defer testsupport.Close(t, left)
	defer testsupport.Close(t, right)
	conn := &ownedConn{Conn: left}
	if err := conn.CloseWrite(); err == nil {
		t.Fatal("unsupported half-close reported EOF sent")
	}
}

func (p *observedPolicy) Protect(fd int) error {
	if fd < 0 {
		return io.ErrClosedPipe
	}
	p.count.Add(1)
	if p.reject {
		return io.ErrClosedPipe
	}
	return nil
}
func (p *observedPolicy) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return []netip.Addr{ip}, ctx.Err()
}

func fixtureNode(t *testing.T, kind, carrier string, xudp bool) *nodeconfig.Config {
	cfg, _ := fixtureNodeWithShutdown(t, kind, carrier, xudp)
	return cfg
}

func fixtureNodeWithShutdown(t *testing.T, kind, carrier string, xudp bool) (*nodeconfig.Config, func()) {
	t.Helper()
	id := testsupport.Certificates(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg := &nodeconfig.Config{Protocol: kind, Seed: []byte("0123456789abcdef0123456789abcdef"), TLS: id.ClientTLS.Clone(), Pin: id.Pin, Path: "/hyraken.pro/Tunnel", Transport: carrier, Suite: "chacha20-poly1305", Congestion: "beast", Connections: 1, Mode: "flash", Scenario: "bulk"}
	if xudp {
		cfg.PacketEncoding = "xudp"
	}
	var shutdown func()
	if kind == "hyrakenx" {
		listener, err := x.Listen("127.0.0.1:0", id.ServerTLS, cfg.Seed)
		if err != nil {
			t.Fatal(err)
		}
		serverDone := make(chan struct{})
		var streamWorkers sync.WaitGroup
		shutdown = func() {
			cancel()
			// The accepted peer must emit its authenticated CLOSE while the
			// shared UDP transport is still alive, then join its stream workers.
			<-serverDone
			_ = listener.Close()
		}
		t.Cleanup(shutdown)
		cfg.Address = listener.Addr().String()
		go func() {
			defer close(serverDone)
			peer, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			defer streamWorkers.Wait()
			defer testsupport.Close(t, peer)
			for {
				conn, network, target, err := peer.AcceptStream(ctx)
				if err != nil {
					return
				}
				streamWorkers.Add(1)
				go func() {
					defer streamWorkers.Done()
					defer func() { _ = conn.Close() }() // Protocol abort may return a cancel-close error; the client physical release is asserted below.
					if network == "udp" {
						packet := x.NewStreamPacketConn(conn, M.ParseSocksaddr(target))
						echoPacket(ctx, packet)
					} else {
						_, _ = io.Copy(conn, conn)
					}
				}()
			}
		}()
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server, err := pro.NewServer(ctx, pro.ServerConfig{Seed: string(cfg.Seed), Path: cfg.Path, Transport: carrier, Suite: cfg.Suite, Congestion: "beast", PacketEncoding: cfg.PacketEncoding})
		if err != nil {
			t.Fatal(err)
		}
		serverTLS := id.ServerTLS.Clone()
		serverTLS.ClientAuth = tls.NoClientCert
		serverTLS.ClientCAs = nil
		t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })
		shutdown = func() { _ = server.Close(); _ = listener.Close(); cancel() }
		cfg.Address = listener.Addr().String()
		cfg.TLS.Certificates = nil
		go func() { _ = server.Serve(listener, serverTLS) }()
		go func() {
			for {
				conn, err := server.Accept(ctx)
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = conn.Close() }() // Protocol abort may return a cancel-close error; the client physical release is asserted below.
					if conn.Network() == "xudp" {
						echoPacket(ctx, pro.NewXUDPServerConn(conn))
					} else if conn.Network() == "udp" {
						echoPacket(ctx, &fixedPacket{Conn: conn, target: M.ParseSocksaddr(conn.Target())})
					} else {
						_, _ = io.Copy(conn, conn)
					}
				}()
			}
		}()
	}
	return cfg, shutdown
}

func echoPacket(ctx context.Context, packet net.PacketConn) {
	defer func() { _ = packet.Close() }() // The real protocol fixture owns final cancellation.
	buffer := make([]byte, 65507)
	for {
		_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		if _, err = packet.WriteTo(buffer[:n], addr); err != nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// Readiness is a real authenticated transport receipt, not NewClient validation.
func TestReadyAuthenticatesXAndProUsingProtectedOwnedSockets(t *testing.T) {
	for _, test := range []struct{ name, protocol, carrier string }{{"X", "hyrakenx", ""}, {"ProTCP", "hyraken-pro", "tcp"}, {"ProGRPC", "hyraken-pro", "grpc"}} {
		t.Run(test.name, func(t *testing.T) {
			cfg := fixtureNode(t, test.protocol, test.carrier, false)
			policy := &observedPolicy{}
			client, err := NewClient(context.Background(), cfg, policy)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if policy.count.Load() != 0 {
				t.Fatal("constructor started network I/O")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := client.Ready(ctx); err != nil {
				t.Fatalf("synthetic node authentication failed: %v", err)
			}
			if policy.count.Load() != 1 || client.Stats().PhysicalOpen != 1 {
				t.Fatal("readiness has no protected physical owner")
			}
			conn, err := client.DialTCP(ctx, "echo.test:7")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }() // Protocol abort may return a cancel-close error; the client physical release is asserted below.
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			payload := []byte("real encrypted protocol round trip")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			read := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, read); err != nil || !bytes.Equal(read, payload) {
				t.Fatal("authenticated byte stream did not round trip")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if client.Stats().PhysicalOpen != 0 {
				t.Fatal("close retained a physical socket admission")
			}
		})
	}
}

// Rejecting protect must prevent a TCP connect and release its in-construction
// owner; reporting a successful handshake would bypass Android's VPN boundary.
func TestProtectRejectionPreventsProtocolTrafficAndReturnsPhysicalSlot(t *testing.T) {
	cfg := fixtureNode(t, "hyraken-pro", "tcp", false)
	policy := &observedPolicy{reject: true}
	client, err := NewClient(context.Background(), cfg, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Ready(ctx); err == nil {
		t.Fatal("protect rejection produced a ready transport")
	}
	if client.Stats().PhysicalOpen != 0 {
		t.Fatal("failed protect retained its physical slot")
	}
}

// Actual adapter framing must retain complete datagrams, empty Pro packets and
// fixed X targets, while rejecting overflow before a partial write.
func TestActualProtocolDatagramsPreserveBoundariesAndRejectOverflow(t *testing.T) {
	for _, test := range []struct {
		name, kind string
		xudp       bool
		sizes      []int
		reject     int
	}{{"X", "hyrakenx", false, []int{1, 512, 1024}, 1025}, {"ProUDP", "hyraken-pro", false, []int{0, 1, 1232, 65507}, 65508}, {"ProXUDP", "hyraken-pro", true, []int{0, 1, 1232, 65507}, 65508}} {
		t.Run(test.name, func(t *testing.T) {
			cfg := fixtureNode(t, test.kind, "tcp", test.xudp)
			client, err := NewClient(context.Background(), cfg, &observedPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			defer testsupport.Close(t, client)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := client.Ready(ctx); err != nil {
				t.Fatal(err)
			}
			packet, err := client.DialPacket(ctx, "echo.test:7")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = packet.Close() }() // Datagram abort can return the mature QUIC cancel-close error; client ownership is checked separately.
			target := M.ParseSocksaddr("echo.test:7")
			for _, size := range test.sizes {
				payload := bytes.Repeat([]byte{0x51}, size)
				_ = packet.SetDeadline(time.Now().Add(2 * time.Second))
				n, err := packet.WriteTo(payload, target)
				if err != nil || n != size {
					t.Fatalf("size %d write failed", size)
				}
				reply := make([]byte, 65507)
				n, addr, err := packet.ReadFrom(reply)
				if err != nil || n != size || addr.String() != target.String() || !bytes.Equal(reply[:n], payload) {
					t.Fatalf("size %d lost a datagram boundary or empty-packet semantics", size)
				}
			}
			if n, err := packet.WriteTo(make([]byte, test.reject), target); err == nil || n != 0 {
				t.Fatal("overflow accepted or partially written")
			}
			if test.kind == "hyrakenx" {
				if n, err := packet.WriteTo(nil, target); err == nil || n != 0 {
					t.Fatal("X empty packet was accepted")
				}
			}
			if got := client.Stats().PhysicalOpen; got > 2 {
				t.Fatal("packetOnly pool escaped hard physical admission")
			}
		})
	}
}

// Canceling an owned client must wake actual blocked reads, not only clear counters.
func TestClientCancellationClosesRealStreamsAndPhysicalSockets(t *testing.T) {
	cfg := fixtureNode(t, "hyraken-pro", "tcp", false)
	ctx, cancel := context.WithCancel(context.Background())
	client, err := NewClient(ctx, cfg, &observedPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, client)
	openCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := client.Ready(openCtx); err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialTCP(openCtx, "echo.test:7")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); result <- err }()
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled real stream returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation failed to wake a real stream")
	}
	_ = client.Close()
	if client.Stats().PhysicalOpen != 0 {
		t.Fatal("cancellation retained physical sockets")
	}
}

// Source pool hints must not multiply actual concurrent physical dials.
func TestConcurrentProAssociationsUseOneNormalAndOnePacketOnlySocket(t *testing.T) {
	cfg := fixtureNode(t, "hyraken-pro", "tcp", true)
	client, err := NewClient(context.Background(), cfg, &observedPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	errors := make(chan error, 12)
	for i := 0; i < 12; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			packet, err := client.DialPacket(ctx, "echo.test:7")
			if err != nil {
				errors <- err
				return
			}
			defer func() { _ = packet.Close() }() // Datagram abort can return the mature QUIC cancel-close error; client ownership is checked separately.
			_, err = packet.WriteTo([]byte{1}, M.ParseSocksaddr("echo.test:7"))
			if err != nil {
				errors <- err
			}
		}()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	if stats := client.Stats(); stats.PhysicalPeak > 2 || stats.PhysicalOpen > 2 {
		t.Fatal("pool expanded past mobile physical gate")
	}
}

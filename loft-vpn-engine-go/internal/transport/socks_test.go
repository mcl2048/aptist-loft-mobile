package transport

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	socks "github.com/sagernet/sing/protocol/socks"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
)

type socksEcho struct{}

func (socksEcho) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() { _ = conn.Close() }() // The parent fixture owns final connection cleanup.
	if err := N.ReportConnHandshakeSuccess(conn, conn); err != nil {
		return
	}
	payload, err := io.ReadAll(conn)
	if err == nil {
		_, _ = conn.Write(append([]byte("reply:"), payload...))
	}
}
func (socksEcho) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() { _ = conn.Close() }() // Control cancellation owns final association cleanup.
	// The mature server caches its first datagram. ReadCachedPacket preserves a
	// valid zero-length payload; ReadOnceFrom would characterize it as EOF.
	if cached, ok := conn.(interface{ ReadCachedPacket() *N.PacketBuffer }); ok {
		first := cached.ReadCachedPacket()
		if first != nil && first.Buffer != nil {
			response := buf.NewSize(3 + M.MaxSocksaddrLength + first.Buffer.Len())
			response.Resize(3+M.MaxSocksaddrLength, 0)
			_, _ = response.Write(first.Buffer.Bytes())
			_ = conn.WritePacket(response, first.Destination)
			first.Buffer.Release()
			N.PutPacketBuffer(first)
		}
	}
	buffer := buf.NewSize(65507)
	defer buffer.Release()
	for {
		buffer.Reset()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		target, err := conn.ReadPacket(buffer)
		if err != nil {
			return
		}
		response := buf.NewSize(3 + M.MaxSocksaddrLength + buffer.Len())
		response.Resize(3+M.MaxSocksaddrLength, 0)
		_, _ = response.Write(buffer.Bytes())
		if err := conn.WritePacket(response, target); err != nil {
			return
		}
	}
}

// Real SOCKS5 username/password, CONNECT half-close and UDP_ASSOCIATE use the
// protected dialer; the unused direct-packet fallback is never required.
func TestActualSocksTCPAndUDPUseProtectedAssociationSockets(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, listener)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authenticator := auth.NewAuthenticator([]auth.User{{Username: "synthetic-user", Password: "synthetic-password"}})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer testsupport.Close(t, conn)
				_ = socks.HandleConnectionEx(ctx, conn, bufio.NewReader(conn), authenticator, socksEcho{}, nil, 2*time.Second, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
			}()
		}
	}()
	policy := &observedPolicy{}
	cfg := &nodeconfig.Config{Protocol: "socks5", Address: listener.Addr().String(), Username: "synthetic-user", Password: "synthetic-password"}
	client, err := NewClient(ctx, cfg, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, client)
	opening, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := client.Ready(opening); err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialTCP(opening, "echo.test:7")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("late"))
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "reply:late" {
		t.Fatal("SOCKS CONNECT lost half-close/reverse bytes")
	}
	_ = conn.Close()
	packet, err := client.DialPacket(opening, "echo.test:7")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, packet)
	target := M.ParseSocksaddr("echo.test:7")
	for _, payload := range [][]byte{nil, []byte("udp packet"), bytes.Repeat([]byte{3}, 65000)} {
		_ = packet.SetDeadline(time.Now().Add(2 * time.Second))
		if n, err := packet.WriteTo(payload, target); err != nil || n != len(payload) {
			t.Fatal("SOCKS UDP write failed")
		}
		buffer := make([]byte, 65507)
		n, address, err := packet.ReadFrom(buffer)
		if err != nil || n != len(payload) || address.String() != target.String() || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("SOCKS UDP size %d read count=%d error=%v", len(payload), n, err)
		}
	}
	_ = client.Close()
	if stats := client.Stats(); stats.PhysicalOpen != 0 || stats.ProtectedSockets < 5 {
		t.Fatal("SOCKS control/data sockets were not protected and released")
	}
}

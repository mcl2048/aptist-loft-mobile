package testsupport

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	socks "github.com/sagernet/sing/protocol/socks"
)

// SocksServer owns a real mature SOCKS5 authentication/echo endpoint for host
// tests. No credential from a private input file is used by this helper.
func SocksServer(t *testing.T, username, password string) string {
	return SocksServerWithHandler(t, username, password, socksEcho{})
}

type SocksHandler interface {
	NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc)
	NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc)
}

// SocksServerWithHandler keeps the mature SOCKS auth/framing boundary while
// allowing controlled host tests to prove the actual transmitted FQDN target.
func SocksServerWithHandler(t *testing.T, username, password string, handler SocksHandler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	authenticator := auth.NewAuthenticator([]auth.User{{Username: username, Password: password}})
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = struct{}{}
			mu.Unlock()
			go func() {
				defer func() { _ = conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
				_ = socks.HandleConnectionEx(ctx, conn, bufio.NewReader(conn), authenticator, handler, nil, 2*time.Second, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
			}()
		}
	}()
	return listener.Addr().String()
}

type socksEcho struct{}

func (socksEcho) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() { _ = conn.Close() }() // The tracked TCP/control fixture owns final cleanup.
	if N.ReportConnHandshakeSuccess(conn, conn) != nil {
		return
	}
	request, err := io.ReadAll(conn)
	if err == nil {
		_, _ = conn.Write(request)
	}
}

func (socksEcho) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() { _ = conn.Close() }() // Control cancellation owns the association's final cleanup.
	if cached, ok := conn.(interface{ ReadCachedPacket() *N.PacketBuffer }); ok {
		first := cached.ReadCachedPacket()
		if first != nil && first.Buffer != nil {
			writeSocksReply(conn, first.Buffer.Bytes(), first.Destination)
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
		writeSocksReply(conn, buffer.Bytes(), target)
	}
}

func writeSocksReply(conn N.PacketConn, payload []byte, destination M.Socksaddr) {
	response := buf.NewSize(3 + M.MaxSocksaddrLength + len(payload))
	response.Resize(3+M.MaxSocksaddrLength, 0)
	_, _ = response.Write(payload)
	_ = conn.WritePacket(response, destination)
}

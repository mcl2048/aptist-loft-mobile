//go:build with_gvisor

package vpn

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	x "loft.local/hyrakenx"
	"net.aptist.loft/loft-vpn-engine-go/internal/nodeconfig"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
	"testing"
)

func fixtureTarget(target string) (string, error) {
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort("127.0.0.1", port), nil
}

func relayFixtureTCP(stream, remote net.Conn) {
	results := make(chan error, 2)
	copySide := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			}
		}
		results <- err
	}
	go copySide(remote, stream)
	go copySide(stream, remote)
	if err := <-results; err != nil {
		_ = stream.Close()
		_ = remote.Close()
	}
	if err := <-results; err != nil {
		_ = stream.Close()
		_ = remote.Close()
	}
}

func privacyXNode(t *testing.T, admit func(string, string) bool) *nodeconfig.Config {
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
		defer func() { _ = peer.Close() }()
		for {
			stream, network, target, err := peer.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = stream.Close() }()
				if !admit(network, target) {
					return
				}
				address, err := fixtureTarget(target)
				if err != nil {
					return
				}
				remote, err := net.DialTimeout(network, address, time.Second)
				if err != nil {
					return
				}
				defer func() { _ = remote.Close() }()
				if network == "tcp" {
					relayFixtureTCP(stream, remote)
					return
				}
				packet := x.NewStreamPacketConn(stream, M.ParseSocksaddr(target))
				data := make([]byte, 1024)
				for {
					n, replyTarget, err := packet.ReadFrom(data)
					if err != nil {
						return
					}
					if _, err := remote.Write(data[:n]); err != nil {
						return
					}
					n, err = remote.Read(data)
					if err != nil {
						return
					}
					if _, err := packet.WriteTo(data[:n], replyTarget); err != nil {
						return
					}
				}
			}()
		}
	}()
	return &nodeconfig.Config{Protocol: "hyrakenx", Address: listener.Addr().String(), Seed: seed, TLS: identity.ClientTLS.Clone(), Pin: identity.Pin, Mode: "flash", Scenario: "bulk"}
}

type privacySocksRouter struct{ admit func(string, string) bool }

func (h privacySocksRouter) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() { _ = conn.Close() }()
	if !h.admit("tcp", destination.String()) {
		return
	}
	address, err := fixtureTarget(destination.String())
	if err != nil {
		return
	}
	remote, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return
	}
	defer func() { _ = remote.Close() }()
	if N.ReportConnHandshakeSuccess(conn, remote) != nil {
		return
	}
	relayFixtureTCP(conn, remote)
}

func (h privacySocksRouter) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() { _ = conn.Close() }()
	var remote net.Conn
	var current M.Socksaddr
	defer func() {
		if remote != nil {
			_ = remote.Close()
		}
	}()
	reply := func(payload []byte, target M.Socksaddr) bool {
		if remote == nil {
			if !h.admit("udp", target.String()) {
				return false
			}
			address, err := fixtureTarget(target.String())
			if err != nil {
				return false
			}
			remote, err = net.DialTimeout("udp", address, time.Second)
			if err != nil {
				return false
			}
			current = target
		}
		if current.String() != target.String() {
			return false
		}
		_ = remote.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := remote.Write(payload); err != nil {
			return false
		}
		data := make([]byte, 65507)
		n, err := remote.Read(data)
		if err != nil {
			return false
		}
		response := buf.NewSize(3 + M.MaxSocksaddrLength + n)
		response.Resize(3+M.MaxSocksaddrLength, 0)
		_, _ = response.Write(data[:n])
		return conn.WritePacket(response, target) == nil
	}
	if cached, ok := conn.(interface{ ReadCachedPacket() *N.PacketBuffer }); ok {
		first := cached.ReadCachedPacket()
		if first != nil && first.Buffer != nil {
			ok := reply(first.Buffer.Bytes(), first.Destination)
			first.Buffer.Release()
			N.PutPacketBuffer(first)
			if !ok {
				return
			}
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
		if !reply(buffer.Bytes(), target) {
			return
		}
	}
}

func privacySocksNode(t *testing.T, admit func(string, string) bool) *nodeconfig.Config {
	address := testsupport.SocksServerWithHandler(t, "synthetic-user", "synthetic-password", privacySocksRouter{admit})
	return &nodeconfig.Config{Protocol: "socks5", Address: address, Username: "synthetic-user", Password: "synthetic-password"}
}

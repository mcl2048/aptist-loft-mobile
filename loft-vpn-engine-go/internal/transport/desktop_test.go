package transport

import (
	"context"
	"net"
	"net.aptist.loft/loft-vpn-engine-go/internal/testsupport"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Go's DNS resolver selects UDP framing through net.PacketConn. An ownership
// wrapper that hides this interface sends TCP framing to a UDP DNS socket.
func TestDesktopResolverPreservesUDPFramingAndReturnsSocketOwner(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer testsupport.Close(t, server)
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			var message dnsmessage.Message
			if message.Unpack(buffer[:n]) != nil || len(message.Questions) != 1 {
				continue
			}
			message.Response = true
			message.RecursionAvailable = true
			message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			wire, err := message.Pack()
			if err != nil {
				return
			}
			_, _ = server.WriteTo(wire, peer)
		}
	}()
	policy := NewDesktopPolicy()
	resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return policy.dialResolver(ctx, network, server.LocalAddr().String())
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	addresses, err := resolver.LookupNetIP(ctx, "ip4", "node.test")
	if err != nil || len(addresses) != 1 || addresses[0].String() != "127.0.0.1" {
		t.Fatal("ownership wrapper changed actual UDP DNS framing")
	}
	open, peak, receipts := policy.ResolverStats()
	if open != 0 || peak != 1 || receipts != 1 {
		t.Fatal("resolver did not return its actual socket owner")
	}
}

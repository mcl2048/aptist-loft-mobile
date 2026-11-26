//go:build with_gvisor

package vpn

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/waiter"
	tun "github.com/sagernet/sing-tun"
)

// A gVisor configuration receipt must correspond to actual endpoint commitments,
// not a mobile quota printed alongside multi-MiB upstream buffers.
func TestMobileStackUsesBoundedTCPBufferCommitments(t *testing.T) {
	endpoint := channel.New(16, 1280, "")
	ipStack, err := tun.NewGVisorStackWithMobileLimits(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer ipStack.Close()
	var receive tcpip.TCPReceiveBufferSizeRangeOption
	var send tcpip.TCPSendBufferSizeRangeOption
	if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		t.Fatal(err)
	}
	if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		t.Fatal(err)
	}
	if receive.Default != 16384 || receive.Max != 32768 || send.Default != 16384 || send.Max != 32768 {
		t.Fatal("actual TCP stack retained upstream multi-MiB buffer commitments")
	}
	var queue waiter.Queue
	conn, e := ipStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &queue)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if value := conn.SocketOptions().GetReceiveBufferSize(); value != 16384 {
		t.Fatal("new actual endpoint did not consume mobile receive-buffer policy")
	}
}

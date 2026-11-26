//go:build with_gvisor

package tun

import (
	"context"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
)

// NewGVisorStackWithMobileLimits applies the owned mobile buffer commitments.
func NewGVisorStackWithMobileLimits(endpoint stack.LinkEndpoint) (*stack.Stack, error) {
	ipStack, err := NewGVisorStack(endpoint)
	if err != nil {
		return nil, err
	}
	if err := ApplyMobileTCPBuffers(ipStack); err != nil {
		ipStack.Close()
		return nil, err
	}
	return ipStack, nil
}

// ApplyMobileTCPBuffers establishes commitments before forwarding endpoints exist.
func ApplyMobileTCPBuffers(ipStack *stack.Stack) error {
	receive := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 16384, Max: 32768}
	send := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 16384, Max: 32768}
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &receive); err != nil {
		return gonet.TranslateNetstackError(err)
	}
	if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &send); err != nil {
		return gonet.TranslateNetstackError(err)
	}
	return nil
}

// NewMobileTCPForwarder limits pending handshakes at their actual creator.
func NewMobileTCPForwarder(ctx context.Context, ipStack *stack.Stack, handler Handler) *TCPForwarder {
	forwarder := NewTCPForwarder(ctx, ipStack, handler)
	forwarder.forwarder = tcp.NewForwarder(ipStack, 0, 64, forwarder.Forward)
	return forwarder
}

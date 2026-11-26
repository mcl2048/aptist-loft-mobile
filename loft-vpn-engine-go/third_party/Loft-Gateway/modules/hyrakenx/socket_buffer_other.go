//go:build !linux

package hyrakenx

import "net"

// Keep the platform's existing policy where Linux's doubled SO_*BUF and host
// cap inspection are unavailable.
func configureOwnedUDPSocket(net.PacketConn) {}

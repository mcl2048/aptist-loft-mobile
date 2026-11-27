//go:build !linux

package hyrakenx

import "net"

// Other platforms retain the original PacketConn path and expose no descriptor.
func gateECNEnabled(net.PacketConn) bool { return false }

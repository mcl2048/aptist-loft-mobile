//go:build !linux

package quic

// The opt-in marker adds no capability on platforms without the locked Linux
// message contract; wrapConn continues along its unchanged original branches.
func wrapMessageConn(MessagePacketConn) rawConn { return nil }

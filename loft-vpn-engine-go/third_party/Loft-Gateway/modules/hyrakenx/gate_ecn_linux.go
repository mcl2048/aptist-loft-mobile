//go:build linux

package hyrakenx

import (
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ECNEnabled opts this authentication wrapper into message I/O, never descriptor
// I/O. NewGateConn only observes the owner's existing socket receive options.
func (g *GateConn) ECNEnabled() bool { return g.ecnEnabled }

func gateECNEnabled(conn net.PacketConn) bool {
	if disabled, err := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_ECN")); err == nil && disabled {
		return false
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return false
	}
	raw, err := udp.SyscallConn()
	if err != nil {
		return false
	}
	enabled := false
	err = raw.Control(func(fd uintptr) {
		addr, err := unix.Getsockname(int(fd))
		if err != nil {
			return
		}
		v4, e4 := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS)
		if _, ok := addr.(*unix.SockaddrInet4); ok {
			enabled = e4 == nil && v4 != 0
			return
		}
		if _, ok := addr.(*unix.SockaddrInet6); !ok {
			return
		}
		v6, e6 := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS)
		v6Only, onlyErr := unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		enabled = e6 == nil && v6 != 0 && onlyErr == nil && (v6Only != 0 || e4 == nil && v4 != 0)
	})
	return err == nil && enabled
}

// ReadMsgUDP returns metadata only for the same complete authenticated datagram.
// Scratch is private to this call because listeners permit concurrent Gate use.
func (g *GateConn) ReadMsgUDP(out, outOOB []byte) (int, int, int, *net.UDPAddr, error) {
	udp, ok := g.inner.(*net.UDPConn)
	if !ok {
		return 0, 0, 0, nil, errors.ErrUnsupported
	}
	packet := gateReadPacketBuffer(out)
	var metadata [128]byte
	for {
		n, nn, flags, addr, err := udp.ReadMsgUDP(packet[:], metadata[:])
		if err != nil {
			return 0, 0, 0, nil, err
		}
		if nn < 0 || nn > len(metadata) || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || !g.authenticatePacket(packet[:], n, len(out)) {
			continue
		}
		// Only the metadata bytes actually written can overlap the authenticated
		// source. Keep the original metadata-then-body output order, snapshotting
		// accepted QUIC ciphertext only when that copy would overwrite its source.
		bodySource := packet[gateHeaderSize:n]
		if gateReceiveSlicesOverlap(bodySource, outOOB[:min(len(outOOB), nn)]) {
			var body [maxInnerQUICPacket]byte
			bodySource = body[:copy(body[:], bodySource)]
		}
		copied := copy(outOOB, metadata[:nn])
		if copied < nn {
			flags |= unix.MSG_CTRUNC
		}
		return copy(out, bodySource), copied, flags, addr, nil
	}
}

// gateReceiveSlicesOverlap uses Go 1.27.4 crypto/internal/fips140/alias.AnyOverlap's
// live-byte address comparisons. It ignores storage beyond slice length and never
// performs pointer arithmetic, pointer reconstruction or unsafe memory access.
// This only decides whether receive metadata needs a call-owned body snapshot.
func gateReceiveSlicesOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// WriteMsgUDP authenticates the entire QUIC packet before forwarding its ECN
// control message. It never exports RawConn, supports GSO or retains input slices.
func (g *GateConn) WriteMsgUDP(packet, oob []byte, addr *net.UDPAddr) (int, int, error) {
	udp, ok := g.inner.(*net.UDPConn)
	if !ok {
		return 0, 0, errors.ErrUnsupported
	}
	if addr == nil || addr.Port < 0 || addr.Port > 65535 {
		return 0, 0, errors.New("hyrakenx: invalid UDP message destination")
	}
	// AddrPort converts the public int port to uint16. Check before conversion
	// so malformed ports cannot wrap into a different authenticated destination.
	destination := addr.AddrPort()
	if !destination.IsValid() {
		return 0, 0, errors.New("hyrakenx: invalid UDP message IP")
	}
	if len(oob) > 128 {
		return 0, 0, errors.New("hyrakenx: UDP message metadata exceeds bounded capacity")
	}
	for data := oob; len(data) > 0; {
		header, _, rest, err := unix.ParseOneSocketControlMessage(data)
		if err != nil {
			return 0, 0, err
		}
		if header.Level == unix.SOL_UDP && header.Type == unix.UDP_SEGMENT {
			return 0, 0, errors.New("hyrakenx: Gate datagrams cannot be segmented")
		}
		data = rest
	}
	var wrapped [gateHeaderSize + maxInnerQUICPacket]byte
	size, err := g.wrapPacket(wrapped[:], packet)
	if err != nil {
		return 0, 0, err
	}
	// This standard-library entry point uses concrete sockaddr storage, avoiding
	// the interface sockaddr allocation of WriteMsgUDP without changing I/O.
	n, nn, err := udp.WriteMsgUDPAddrPort(wrapped[:size], oob, destination)
	if err != nil {
		return 0, nn, err
	}
	if n != size || nn != len(oob) {
		return 0, nn, io.ErrShortWrite
	}
	return len(packet), nn, nil
}

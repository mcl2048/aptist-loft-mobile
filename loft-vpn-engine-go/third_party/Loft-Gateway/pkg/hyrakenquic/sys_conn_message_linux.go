//go:build linux

package quic

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"golang.org/x/sys/unix"
)

type messageConn struct {
	MessagePacketConn
	// rawConn has one receiver. Persist bounded OOB storage rather than escape
	// a new array through the wrapper interface on every authenticated packet.
	rxOOB [128]byte
}

func wrapMessageConn(conn MessagePacketConn) rawConn {
	if !isECNEnabled() {
		return nil
	}
	return &messageConn{MessagePacketConn: conn}
}

func (*messageConn) capabilities() connCapabilities { return connCapabilities{DF: true, ECN: true} }

func (c *messageConn) ReadPacket() (receivedPacket, error) {
	for {
		buffer := getPacketBuffer()
		buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
		n, nn, flags, addr, err := c.ReadMsgUDP(buffer.Data, c.rxOOB[:])
		if err != nil {
			buffer.Release()
			return receivedPacket{}, err
		}
		if n <= 0 || n > len(buffer.Data) || nn < 0 || nn > len(c.rxOOB) || addr == nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			buffer.Release()
			continue
		}
		ecn, valid := messageECN(c.rxOOB[:nn])
		if !valid {
			buffer.Release()
			continue
		}
		return receivedPacket{remoteAddr: addr, rcvTime: monotime.Now(), data: buffer.Data[:n], buffer: buffer, ecn: ecn}, nil
	}
}

// Invalid optional metadata drops just this datagram. It must never kill an
// otherwise healthy authenticated transport or manufacture a CE observation.
func messageECN(data []byte) (protocol.ECN, bool) {
	ecn := protocol.ECNUnsupported
	for len(data) > 0 {
		header, body, rest, err := unix.ParseOneSocketControlMessage(data)
		if err != nil {
			return protocol.ECNUnsupported, false
		}
		if header.Level == unix.IPPROTO_IP && header.Type == msgTypeIPTOS {
			if len(body) != 1 {
				return protocol.ECNUnsupported, false
			}
			ecn = protocol.ParseECNHeaderBits(body[0] & ecnMask)
		}
		if header.Level == unix.IPPROTO_IPV6 && header.Type == unix.IPV6_TCLASS {
			if len(body) != 4 {
				return protocol.ECNUnsupported, false
			}
			ecn = protocol.ParseECNHeaderBits(uint8(binary.NativeEndian.Uint32(body)) & ecnMask)
		}
		data = rest
	}
	return ecn, true
}

func (c *messageConn) WritePacket(packet []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	if gsoSize != 0 {
		return 0, errors.New("QUIC message wrapper does not support GSO")
	}
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp == nil || udp.IP == nil {
		return 0, errors.New("QUIC message wrapper requires a UDP address")
	}
	if ecn == protocol.ECNUnsupported && len(packetInfoOOB) == 0 {
		// A bleached path or an old peer needs no message metadata. Retain the
		// same provider's authenticated packet entry, without unused OOB scratch.
		n, err := c.MessagePacketConn.WriteTo(packet, udp)
		if n < 0 || n > len(packet) {
			return 0, io.ErrShortWrite
		}
		if err != nil {
			return n, err
		}
		if n != len(packet) {
			return n, io.ErrShortWrite
		}
		return n, nil
	}
	// Shared-listener writers may run concurrently. This scratch is call-owned,
	// and optional ECN never appends into the caller's packet-info backing array.
	var storage [128]byte
	if len(packetInfoOOB) > len(storage)-unix.CmsgSpace(4) {
		return 0, errors.New("QUIC message wrapper packet info exceeds bounded OOB capacity")
	}
	oob := storage[:copy(storage[:], packetInfoOOB)]
	if ecn != protocol.ECNUnsupported {
		if udp.IP.To4() != nil {
			oob = appendIPv4ECNMsg(oob, ecn)
		} else {
			oob = appendIPv6ECNMsg(oob, ecn)
		}
	}
	n, nn, err := c.WriteMsgUDP(packet, oob, udp)
	if n < 0 || n > len(packet) {
		return 0, io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	if n != len(packet) || nn != len(oob) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

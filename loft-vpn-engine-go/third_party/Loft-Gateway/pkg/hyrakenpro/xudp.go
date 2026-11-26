package hyrakenpro

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

const MaxXUDPFrame = 2 + 512 + 2 + 65507
const XUDPTarget = "v1.mux.cool:666"

var ErrXUDPControl = errors.New("hyrakenpro: XUDP control frame")

// XUDPAddr preserves domain names without resolving them at the tunnel edge.
type XUDPAddr string

func (a XUDPAddr) Network() string { return "udp" }
func (a XUDPAddr) String() string  { return string(a) }

type XUDPEncoder struct{ started bool }

func (e *XUDPEncoder) Encode(p []byte, addr net.Addr) ([]byte, error) {
	if len(p) > maxPacket {
		return nil, io.ErrShortBuffer
	}
	if addr == nil {
		return nil, errors.New("hyrakenpro: missing XUDP destination")
	}
	if err := validateTarget(addr.String()); err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(addr.String())
	n, _ := strconv.Atoi(port)
	meta := []byte{0, 0, 2, 1, 2, byte(n >> 8), byte(n)}
	if !e.started {
		meta[2] = 1
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			meta = append(meta, 1)
			v := ip.As4()
			meta = append(meta, v[:]...)
		} else {
			if ip.Zone() != "" {
				return nil, errors.New("hyrakenpro: XUDP IPv6 zone unsupported")
			}
			meta = append(meta, 3)
			v := ip.As16()
			meta = append(meta, v[:]...)
		}
	} else {
		if len(host) > 255 || strings.ContainsAny(host, "\x00") {
			return nil, errors.New("hyrakenpro: invalid XUDP domain")
		}
		meta = append(meta, 2, byte(len(host)))
		meta = append(meta, host...)
	}
	wire := make([]byte, 2+len(meta)+2+len(p))
	binary.BigEndian.PutUint16(wire, uint16(len(meta)))
	copy(wire[2:], meta)
	binary.BigEndian.PutUint16(wire[2+len(meta):], uint16(len(p)))
	copy(wire[4+len(meta):], p)
	e.started = true
	return wire, nil
}

type XUDPDecoder struct{ target XUDPAddr }

func (d *XUDPDecoder) Decode(wire []byte) ([]byte, XUDPAddr, error) {
	bad := func() ([]byte, XUDPAddr, error) { return nil, "", errors.New("hyrakenpro: invalid XUDP envelope") }
	if len(wire) < 6 || len(wire) > MaxXUDPFrame {
		return bad()
	}
	n := int(binary.BigEndian.Uint16(wire))
	if n < 4 || n > 512 || len(wire) < 2+n {
		return bad()
	}
	m := wire[2 : 2+n]
	if m[0] != 0 || m[1] != 0 || m[2] < 1 || m[2] > 4 || m[3]&^byte(3) != 0 {
		return bad()
	}
	target := d.target
	if m[2] == 1 || (m[2] == 2 && len(m) > 4) {
		if len(m) < 8 || m[4] != 2 {
			return bad()
		}
		port := binary.BigEndian.Uint16(m[5:7])
		if port == 0 {
			return bad()
		}
		var host string
		end := 8
		switch m[7] {
		case 1:
			end += 4
			if len(m) < end {
				return bad()
			}
			host = net.IP(m[8:end]).String()
		case 3:
			end += 16
			if len(m) < end {
				return bad()
			}
			host = net.IP(m[8:end]).String()
		case 2:
			if len(m) < 9 || m[8] == 0 {
				return bad()
			}
			end = 9 + int(m[8])
			if len(m) < end {
				return bad()
			}
			host = string(m[9:end])
		default:
			return bad()
		}
		// New may carry the standard eight-byte GlobalID. No private metadata.
		if len(m) != end && (m[2] != 1 || len(m) != end+8) {
			return bad()
		}
		target = XUDPAddr(net.JoinHostPort(host, strconv.Itoa(int(port))))
		if validateTarget(target.String()) != nil {
			return bad()
		}
	} else if len(m) != 4 {
		return bad()
	}
	body := wire[2+n:]
	if m[3]&1 != 0 {
		if len(body) < 2 {
			return bad()
		}
		size := int(binary.BigEndian.Uint16(body))
		if size > maxPacket || len(body) != size+2 {
			return bad()
		}
		body = body[2:]
	} else if len(body) != 0 {
		return bad()
	}
	if m[3]&2 != 0 || m[2] == 3 {
		return nil, "", io.EOF
	}
	if m[2] == 4 || m[3]&1 == 0 {
		return nil, "", ErrXUDPControl
	}
	if target == "" {
		return bad()
	}
	d.target = target
	return body, target, nil
}

type XUDPPacketStream interface {
	net.Conn
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) (int, error)
}

// XUDPConn carries exactly one complete standard Mux.Cool frame per Pro packet.
// Separate locks allow one concurrent reader and writer. Short reads are retryable.
type XUDPConn struct {
	XUDPPacketStream
	readMu, writeMu sync.Mutex
	encoder         XUDPEncoder
	decoder         XUDPDecoder
	wire            []byte
	pending         []byte
	pendingAddr     XUDPAddr
}

// NewXUDPConn creates the initiating endpoint. Responses use NewXUDPServerConn.
func NewXUDPConn(c XUDPPacketStream) *XUDPConn {
	return &XUDPConn{XUDPPacketStream: c, wire: make([]byte, MaxXUDPFrame)}
}
func NewXUDPServerConn(c XUDPPacketStream) *XUDPConn {
	v := NewXUDPConn(c)
	v.encoder.started = true
	return v
}
func (c *XUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	controls := 0
	for c.pendingAddr == "" {
		n, e := c.ReadPacket(c.wire)
		if e != nil {
			return 0, nil, e
		}
		v, a, e := c.decoder.Decode(c.wire[:n])
		if errors.Is(e, ErrXUDPControl) {
			controls++
			if controls >= 1024 {
				c.Close()
				return 0, nil, errors.New("hyrakenpro: XUDP control frame budget")
			}
			continue
		}
		if e != nil {
			c.Close()
			return 0, nil, e
		}
		c.pending, c.pendingAddr = v, a
	}
	if len(p) < len(c.pending) {
		return 0, c.pendingAddr, io.ErrShortBuffer
	}
	n := copy(p, c.pending)
	a := c.pendingAddr
	c.pending = nil
	c.pendingAddr = ""
	return n, a, nil
}
func (c *XUDPConn) WriteTo(p []byte, a net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire, e := c.encoder.Encode(p, a)
	if e != nil {
		return 0, e
	}
	n, e := c.WritePacket(wire)
	if e != nil {
		c.Close()
		return 0, e
	}
	if n != len(wire) {
		c.Close()
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

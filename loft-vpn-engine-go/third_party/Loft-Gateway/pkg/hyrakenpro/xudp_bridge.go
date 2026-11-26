package hyrakenpro

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// XUDPBridgeConn is private authenticated loopback IPC, never the public Pro
// wire format. uint32 framing carries complete envelopes above 65535 bytes.
type XUDPBridgeConn struct {
	net.Conn
	readMu, writeMu sync.Mutex
	pending         []byte
}

func NewXUDPBridgeConn(c net.Conn) *XUDPBridgeConn { return &XUDPBridgeConn{Conn: c} }
func (c *XUDPBridgeConn) ReadPacket(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.pending == nil {
		var h [4]byte
		if _, e := io.ReadFull(c.Conn, h[:]); e != nil {
			return 0, e
		}
		n := binary.BigEndian.Uint32(h[:])
		if n > MaxXUDPFrame {
			return 0, errors.New("hyrakenpro: oversized XUDP bridge envelope")
		}
		c.pending = make([]byte, n)
		if _, e := io.ReadFull(c.Conn, c.pending); e != nil {
			c.pending = nil
			return 0, e
		}
	}
	if len(p) < len(c.pending) {
		return 0, io.ErrShortBuffer
	}
	n := copy(p, c.pending)
	c.pending = nil
	return n, nil
}
func (c *XUDPBridgeConn) WritePacket(p []byte) (int, error) {
	if len(p) > MaxXUDPFrame {
		return 0, io.ErrShortBuffer
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	for _, part := range [][]byte{h[:], p} {
		for len(part) > 0 {
			n, e := c.Conn.Write(part)
			if e != nil {
				return 0, e
			}
			if n == 0 {
				return 0, io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return len(p), nil
}

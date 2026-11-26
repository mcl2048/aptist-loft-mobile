package hyrakenx

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// StreamPacketConn maps one connected UDP destination onto reliable encrypted
// logical records. It preserves datagram boundaries and rejects target changes.
type StreamPacketConn struct {
	conn            net.Conn
	target          net.Addr
	readMu, writeMu sync.Mutex
	readErr         error // Each direction owns its terminal framing error.
	writeErr        error
	writeFrame      [2 + MaxDatagramPayload]byte // Owned by writeMu; cleared before unlocking.
}

func NewStreamPacketConn(conn net.Conn, target net.Addr) *StreamPacketConn {
	return &StreamPacketConn{conn: conn, target: target}
}

func (c *StreamPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	var header [2]byte
	if n, err := io.ReadFull(c.conn, header[:]); err != nil {
		if n != 0 {
			return c.failRead(err)
		}
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n == 0 || n > MaxDatagramPayload {
		return c.failRead(errors.New("hyrakenx: invalid logical UDP length"))
	}
	var packet [MaxDatagramPayload]byte
	if _, err := io.ReadFull(c.conn, packet[:n]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return c.failRead(err)
	}
	if n > len(buffer) {
		return 0, nil, io.ErrShortBuffer
	}
	return copy(buffer, packet[:n]), c.target, nil
}

func (c *StreamPacketConn) WriteTo(packet []byte, destination net.Addr) (int, error) {
	if destination == nil || c.target == nil || destination.String() != c.target.String() {
		return 0, errors.New("hyrakenx: logical UDP target changed")
	}
	if len(packet) == 0 || len(packet) > MaxDatagramPayload {
		return 0, errors.New("hyrakenx: invalid logical UDP payload")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	// Keep the logical length and body in one stream write. streamConn seals
	// each Write independently; splitting the length forces an extra padded
	// AEAD record for small datagrams. The byte stream and size cap stay intact.
	// Association-owned storage avoids an escaping allocation on every WriteTo.
	framed := c.writeFrame[:2+len(packet)]
	defer clear(framed) // Runs before writeMu unlock on success and failure.
	binary.BigEndian.PutUint16(framed[:2], uint16(len(packet)))
	copy(framed[2:], packet)
	if err := writeFull(c.conn, framed); err != nil {
		c.writeErr = err
		_ = c.conn.Close()
		return 0, err
	}
	return len(packet), nil
}

// PacketConn has no half-close contract. Retire a damaged datagram association
// rather than interpret its residual body as a new length. A fully consumed
// datagram with a short caller buffer remains recoverable via ErrShortBuffer.
func (c *StreamPacketConn) failRead(err error) (int, net.Addr, error) {
	c.readErr = err
	_ = c.conn.Close()
	return 0, nil, err
}

func (c *StreamPacketConn) Close() error                       { return c.conn.Close() }
func (c *StreamPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *StreamPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *StreamPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *StreamPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

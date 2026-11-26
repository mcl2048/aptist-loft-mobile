package trafficprofile

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sync"
)

// TCPSlicing is the bounded physical-TCP prefix policy for managed protocols.
// Timing remains in the authenticated DATA scheduler, so fragmentation cannot
// stall HTTP control traffic. This is stream Write granularity, not IP packet
// fragmentation, and a CDN may coalesce these writes again.
type TCPSlicing struct {
	ChunkSizeMin int    `json:"chunk_size_min"`
	ChunkSizeMax int    `json:"chunk_size_max"`
	Threshold    uint64 `json:"threshold"`
}

func normalizeTCPSlicing(p TCPSlicing) TCPSlicing {
	p.ChunkSizeMin = min(max(1, p.ChunkSizeMin), 64<<10)
	p.ChunkSizeMax = min(max(p.ChunkSizeMin, p.ChunkSizeMax), 64<<10)
	if p.Threshold == 0 {
		p.Threshold = 16 << 10
	}
	p.Threshold = min(p.Threshold, 4<<20)
	return p
}

// WrapTCP is only for an outgoing raw TCP socket, after socket options and
// before TLS. It never wraps an accepted inbound, a PacketConn, an opaque
// transport or a QUIC stream. No payload copy, delay, goroutine or queue is
// added. A nil policy preserves the exact old connection identity.
func WrapTCP(conn net.Conn, p *Profile) net.Conn {
	if conn == nil || p == nil || p.TCPSlicing == nil || conn.RemoteAddr() == nil {
		return conn
	}
	switch conn.RemoteAddr().Network() {
	case "tcp", "tcp4", "tcp6":
	default:
		return conn
	}
	return &slicedTCPConn{Conn: conn, policy: normalizeTCPSlicing(*p.TCPSlicing)}
}

type slicedTCPConn struct {
	net.Conn
	writeMu sync.Mutex // Serialize caller Writes; Read/Close/deadline never wait here.
	policy  TCPSlicing
	written uint64
}

func (c *slicedTCPConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	const maxWrites = 512
	total := 0
	for calls := 0; total < len(p); calls++ {
		size := len(p) - total
		if c.written < c.policy.Threshold && calls < maxWrites-1 {
			chunk := c.policy.ChunkSizeMin + rand.IntN(c.policy.ChunkSizeMax-c.policy.ChunkSizeMin+1)
			size = min(size, chunk, int(c.policy.Threshold-c.written))
		}
		n, err := c.Conn.Write(p[total : total+size])
		if n < 0 || n > size {
			return total, fmt.Errorf("TCP slicing: invalid Write count %d for %d bytes", n, size)
		}
		total += n
		// Saturation also guarantees that a long-lived connection cannot wrap
		// its prefix counter and accidentally re-enable fragmentation.
		c.written = min(c.policy.Threshold, c.written+uint64(n))
		if err == nil && n != size {
			err = io.ErrShortWrite
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Retain optional half-close semantics; do not expose raw FD fast paths that
// could bypass Write. Socket policy must be applied before WrapTCP.
func (c *slicedTCPConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}
func (c *slicedTCPConn) CloseRead() error {
	if v, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return v.CloseRead()
	}
	return nil
}

// WrapTCPWithBudget opts an engine into bounded per-Write and lifetime-prefix
// syscall work. Each limit is clamped to 1..512; the final available call
// writes the remainder directly. WrapTCP retains its legacy behavior.
func WrapTCPWithBudget(conn net.Conn, p *Profile, maxWritesPerCall, maxPrefixWrites int) net.Conn {
	if conn == nil || p == nil || p.TCPSlicing == nil || conn.RemoteAddr() == nil {
		return conn
	}
	switch conn.RemoteAddr().Network() {
	case "tcp", "tcp4", "tcp6":
	default:
		return conn
	}
	return &budgetedTCPConn{
		slicedTCPConn:    slicedTCPConn{Conn: conn, policy: normalizeTCPSlicing(*p.TCPSlicing)},
		maxWritesPerCall: min(max(maxWritesPerCall, 1), 512),
		prefixWritesLeft: min(max(maxPrefixWrites, 1), 512),
	}
}

// Embed the existing socket forwarding/half-close contract. Write owns both
// counters under the existing mutex; Close and deadlines never take it.
type budgetedTCPConn struct {
	slicedTCPConn
	maxWritesPerCall int
	prefixWritesLeft int
}

func (c *budgetedTCPConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for calls := 0; total < len(p); calls++ {
		size := len(p) - total
		inPrefix := c.written < c.policy.Threshold && c.prefixWritesLeft > 0
		if inPrefix {
			if calls < c.maxWritesPerCall-1 && c.prefixWritesLeft > 1 {
				chunk := c.policy.ChunkSizeMin + rand.IntN(c.policy.ChunkSizeMax-c.policy.ChunkSizeMin+1)
				size = min(size, chunk, int(c.policy.Threshold-c.written))
			}
			c.prefixWritesLeft-- // Failed attempts also consume physical work.
		}
		n, err := c.Conn.Write(p[total : total+size])
		if n < 0 || n > size {
			return total, fmt.Errorf("TCP slicing: invalid Write count %d for %d bytes", n, size)
		}
		total += n
		// Subtraction before addition makes saturation safe for hostile counts
		// and prevents a long-lived connection from re-entering its prefix.
		c.written += min(uint64(n), c.policy.Threshold-c.written)
		if err == nil && n != size {
			err = io.ErrShortWrite
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

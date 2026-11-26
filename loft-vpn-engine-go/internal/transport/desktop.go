package transport

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// DesktopPolicy is explicit host-only socket ownership for protocol probes.
// It never represents Android VpnService protection or TUN acceptance.
type DesktopPolicy struct {
	mu                         sync.Mutex
	resolverOpen, resolverPeak int
	resolverProtected          uint64
}

// NewDesktopPolicy constructs an inert desktop probe policy.
func NewDesktopPolicy() *DesktopPolicy { return &DesktopPolicy{} }

// Protect confirms an owned host fd; Android never uses this policy.
func (p *DesktopPolicy) Protect(fd int) error {
	if fd < 0 {
		return fail("invalid_host_fd", nil)
	}
	return nil
}

// Resolve owns and bounds resolver sockets and returns at most eight literal IPs.
func (p *DesktopPolicy) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resolver := net.Resolver{PreferGo: true, StrictErrors: true, Dial: p.dialResolver}
	addresses, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, fail("node_resolution_failed", err)
	}
	if len(addresses) == 0 || len(addresses) > 8 {
		return nil, fail("node_resolution_failed", nil)
	}
	return addresses, nil
}

func (p *DesktopPolicy) dialResolver(ctx context.Context, network, address string) (net.Conn, error) {
	p.mu.Lock()
	if p.resolverOpen >= 2 {
		p.mu.Unlock()
		return nil, fail("resolver_socket_limit", nil)
	}
	p.resolverOpen++
	if p.resolverOpen > p.resolverPeak {
		p.resolverPeak = p.resolverOpen
	}
	p.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { p.mu.Lock(); p.resolverOpen--; p.mu.Unlock() }) }
	dialer := net.Dialer{Timeout: 5 * time.Second, Control: func(_ string, _ string, raw syscall.RawConn) error {
		return raw.Control(func(fd uintptr) { p.mu.Lock(); p.resolverProtected++; p.mu.Unlock() })
	}}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		release()
		return nil, err
	}
	owned := &resolverConn{Conn: conn, release: release}
	if packet, ok := conn.(net.PacketConn); ok {
		return &resolverPacketConn{resolverConn: owned, packet: packet}, nil
	}
	return owned, nil
}

type resolverConn struct {
	net.Conn
	release func()
	once    sync.Once
	err     error
}

func (c *resolverConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.release() })
	return c.err
}

type resolverPacketConn struct {
	*resolverConn
	packet net.PacketConn
}

func (c *resolverPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	return c.packet.ReadFrom(buffer)
}
func (c *resolverPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	return c.packet.WriteTo(buffer, address)
}

// ResolverStats returns host-only resolver ownership counters.
func (p *DesktopPolicy) ResolverStats() (int, int, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resolverOpen, p.resolverPeak, p.resolverProtected
}

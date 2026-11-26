package hyrakenx

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"sync"
	"time"
)

const (
	gateHeaderSize     = 20
	gateEpochSeconds   = 30
	maxInnerQUICPacket = 1212 // 1212 + 20 + UDP/IPv6(48) = 1280.
)

// GateConn is a stateless, directional packet authenticator in front of QUIC.
// It suppresses unauthenticated scanner responses; TLS still owns identity and
// QUIC still owns anti-amplification, packet replay and connection state.
// A captured valid outer packet can be replayed, so this is not a replay fence.
type GateConn struct {
	inner net.PacketConn
	key   [32]byte // Immutable after construction, including during fallback hashing.
	role  Role
	tags  [2]gateTagWorkspace
}

// Each direction owns one bounded hash workspace. Its mutex protects all hash
// and scratch mutation; callers that find it busy hash independently instead.
type gateTagWorkspace struct {
	mu        sync.Mutex
	mac       hash.Hash
	direction [1]byte
	sum       [sha256.Size]byte
}

func NewGateConn(conn net.PacketConn, secret []byte, role Role) (*GateConn, error) {
	if conn == nil || role > Server || len(secret) < 32 || len(secret) > 256 {
		return nil, errors.New("hyrakenx: invalid stateless gate configuration")
	}
	key, err := hkdf.Key(sha256.New, secret, nil, "hyrakenx/v1/outer-gate", 32)
	if err != nil {
		return nil, fmt.Errorf("hyrakenx: derive gate key: %w", err)
	}
	g := &GateConn{inner: conn, role: role}
	copy(g.key[:], key)
	clear(key)
	for direction := range g.tags {
		workspace := &g.tags[direction]
		workspace.direction[0] = byte(direction)
		workspace.mac = hmac.New(sha256.New, g.key[:])
		// Prepare the standard HMAC reset state before the first packet.
		workspace.mac.Reset()
	}
	return g, nil
}

func (g *GateConn) tag(direction Role, epoch, packet []byte) [16]byte {
	workspace := &g.tags[direction]
	// Only an uncontended call reuses allocation-free state. Shared-listener
	// peers never wait for another peer's hash or hold this lock over socket I/O.
	if !workspace.mu.TryLock() {
		return g.independentTag(direction, epoch, packet)
	}
	workspace.mac.Reset()
	_, _ = workspace.mac.Write(workspace.direction[:])
	_, _ = workspace.mac.Write(epoch)
	_, _ = workspace.mac.Write(packet)
	var tag [16]byte
	copy(tag[:], workspace.mac.Sum(workspace.sum[:0]))
	workspace.mu.Unlock()
	return tag
}

func (g *GateConn) independentTag(direction Role, epoch, packet []byte) [16]byte {
	mac := hmac.New(sha256.New, g.key[:])
	_, _ = mac.Write([]byte{byte(direction)})
	_, _ = mac.Write(epoch)
	_, _ = mac.Write(packet)
	var tag [16]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func (g *GateConn) ReadFrom(out []byte) (int, net.Addr, error) {
	// One extra byte distinguishes an oversized UDP datagram from an exact-fit one.
	var packet [gateHeaderSize + maxInnerQUICPacket + 1]byte
	for {
		n, addr, err := g.inner.ReadFrom(packet[:])
		if err != nil {
			return 0, nil, err
		}
		if n < gateHeaderSize+1 || n > gateHeaderSize+maxInnerQUICPacket || n-gateHeaderSize > len(out) {
			continue
		}
		epoch := binary.BigEndian.Uint32(packet[:4])
		now := uint32(time.Now().Unix() / gateEpochSeconds)
		if epoch+1 < now || epoch > now+1 {
			continue
		}
		expected := g.tag(g.role^1, packet[:4], packet[gateHeaderSize:n])
		if subtle.ConstantTimeCompare(expected[:], packet[4:gateHeaderSize]) != 1 {
			continue
		}
		return copy(out, packet[gateHeaderSize:n]), addr, nil
	}
}

func (g *GateConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	if len(packet) == 0 || len(packet) > maxInnerQUICPacket {
		return 0, errors.New("hyrakenx: QUIC packet exceeds 1280-byte IPv6 path budget")
	}
	var wrapped [gateHeaderSize + maxInnerQUICPacket]byte
	binary.BigEndian.PutUint32(wrapped[:4], uint32(time.Now().Unix()/gateEpochSeconds))
	copy(wrapped[gateHeaderSize:], packet)
	tag := g.tag(g.role, wrapped[:4], packet)
	copy(wrapped[4:gateHeaderSize], tag[:])
	n, err := g.inner.WriteTo(wrapped[:gateHeaderSize+len(packet)], addr)
	if err != nil {
		return 0, err
	}
	if n != gateHeaderSize+len(packet) {
		return 0, net.ErrClosed
	}
	return len(packet), nil
}

// ReadFromContext is for bounded diagnostics. QUIC uses ReadFrom and closes
// the owned socket to stop it; callers must not use this concurrently with QUIC.
func (g *GateConn) ReadFromContext(ctx context.Context, buffer []byte) (int, net.Addr, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, nil, errors.New("hyrakenx: diagnostic read requires deadline")
	}
	if err := g.inner.SetReadDeadline(deadline); err != nil {
		return 0, nil, err
	}
	defer g.inner.SetReadDeadline(time.Time{})
	n, addr, err := g.ReadFrom(buffer)
	if err != nil && ctx.Err() != nil {
		return 0, nil, ctx.Err()
	}
	return n, addr, err
}

func (g *GateConn) Close() error                       { return g.inner.Close() }
func (g *GateConn) LocalAddr() net.Addr                { return g.inner.LocalAddr() }
func (g *GateConn) SetDeadline(t time.Time) error      { return g.inner.SetDeadline(t) }
func (g *GateConn) SetReadDeadline(t time.Time) error  { return g.inner.SetReadDeadline(t) }
func (g *GateConn) SetWriteDeadline(t time.Time) error { return g.inner.SetWriteDeadline(t) }

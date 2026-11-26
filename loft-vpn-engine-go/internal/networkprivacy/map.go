package networkprivacy

import (
	"errors"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var fakePrefix = netip.MustParsePrefix("198.19.0.0/16")

// FakePrefix returns the immutable pool, separate from TUN/DNS control addresses.
func FakePrefix() netip.Prefix { return fakePrefix }

// Budget is the existing session-owned added-memory ledger.
type Budget interface {
	ReservePacket(int) bool
	ReleasePacket(int)
}

// DNSAllocatorBytes reserves all fixed process-owned address quarantine state.
// Dynamic maps, guards and packet queues share the remainder of the existing
// 8 MiB budget. Stop releases dynamic owners; no domain/payload is kept here.
const DNSAllocatorBytes int64 = 528 * 1024
const DynamicBudgetBytes int64 = (8 << 20) - DNSAllocatorBytes

type addressPool struct {
	mu sync.Mutex
	// -1 is assigned to an entry/live borrower; zero is unused; positive values
	// are monotonic-relative last-advertised expiry deadlines, with no domain.
	deadlines [65534]int64
	cursor    int
	full      bool
	retryAt   int64
	origin    time.Time
}

var processPool = addressPool{origin: time.Now()}
var errAddressExhausted = errors.New("loft.vpn.dns_address_exhausted")

func (p *addressPool) tick(now time.Time) int64 { return max(1, now.Sub(p.origin).Nanoseconds()+1) }

func (p *addressPool) allocate(now time.Time) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tick := p.tick(now)
	if p.full && tick < p.retryAt {
		return netip.Addr{}, errAddressExhausted
	}
	earliest := int64(math.MaxInt64)
	// Scanning is confined to new alias allocation, never flow/packet lookup.
	// At exhaustion cache the earliest eligible deadline, so repeated packets
	// reject in O(1) until expiry or a final lease releases an earlier slot.
	for attempts := 0; attempts < len(p.deadlines); attempts++ {
		index := p.cursor
		p.cursor = (index + 1) % len(p.deadlines)
		deadline := p.deadlines[index]
		if deadline >= 0 && deadline <= tick {
			p.deadlines[index] = -1
			p.full = false
			next := index + 1
			return netip.AddrFrom4([4]byte{198, 19, byte(next >> 8), byte(next)}), nil
		}
		if deadline > tick {
			earliest = min(earliest, deadline)
		}
	}
	p.full = true
	p.retryAt = earliest
	return netip.Addr{}, errAddressExhausted
}

func (p *addressPool) release(address netip.Addr, expires time.Time) {
	bytes := address.As4()
	index := int(bytes[2])<<8 | int(bytes[3])
	index--
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.deadlines[index] != -1 {
		return
	}
	deadline := p.tick(expires)
	p.deadlines[index] = deadline
	if p.full {
		p.retryAt = min(p.retryAt, deadline)
	}
}

type mapEntry struct {
	host    string
	address netip.Addr
	expires time.Time
	refs    int
	cached  bool
}

// Map implements the existing GhostX synthetic-address/reverse-domain pattern
// with finite entries/bytes, passive expiry and live leases. A slot can only be
// reassigned after its final owner and last advertised TTL have both ended.
// Retired/current policy proofs and map authorization are never reused.
type Map struct {
	mu      sync.Mutex
	policy  Policy
	budget  Budget
	closed  bool
	byName  map[string]*mapEntry
	byIP    map[netip.Addr]*mapEntry
	entries int
	bytes   int64
}

// NewMap is inert; entry and map storage is admitted before the first allocation.
func NewMap(policy Policy, budget Budget) *Map { return &Map{policy: policy, budget: budget} }

// Resolve allocates or renews a canonical domain's synthetic routing address.
// This operation does not resolve the domain or prove that it exists.
func (m *Map) Resolve(host string, now time.Time) (netip.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resolveLocked(host, now)
}

// ResolveLease atomically binds a DNS reply to its original domain/address.
// No reclamation or address reassignment can occur between resolve and borrow.
func (m *Map) ResolveLease(host string, now time.Time) (*MappingLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	address, err := m.resolveLocked(host, now)
	if err != nil {
		return nil, err
	}
	entry := m.byIP[address]
	entry.refs++
	return &MappingLease{mapping: m, entry: entry}, nil
}

func (m *Map) resolveLocked(host string, now time.Time) (netip.Addr, error) {
	if !canonicalDomain(host) {
		return netip.Addr{}, errors.New("loft.vpn.invalid_dns_name")
	}
	if m.closed {
		return netip.Addr{}, errors.New("loft.vpn.privacy_retired")
	}
	if entry := m.byName[host]; entry != nil {
		deadline := now.Add(time.Duration(m.policy.DNSTTLSeconds) * time.Second)
		if deadline.After(entry.expires) {
			entry.expires = deadline
		}
		return entry.address, nil
	}
	if m.entries >= m.policy.DNSMapMaxEntries || m.bytes+1024 > int64(m.policy.DNSMapMaxBytes) {
		m.expire(now)
	}
	if m.entries >= m.policy.DNSMapMaxEntries || m.bytes+1024 > int64(m.policy.DNSMapMaxBytes) || !m.budget.ReservePacket(1024) {
		return netip.Addr{}, errors.New("loft.vpn.dns_map_limit")
	}
	address, err := processPool.allocate(now)
	if err != nil {
		m.budget.ReleasePacket(1024)
		return netip.Addr{}, err
	}
	if m.byName == nil {
		m.byName = make(map[string]*mapEntry)
		m.byIP = make(map[netip.Addr]*mapEntry)
	}
	entry := &mapEntry{host: host, address: address, expires: now.Add(time.Duration(m.policy.DNSTTLSeconds) * time.Second), cached: true}
	m.byName[host], m.byIP[address] = entry, entry
	m.entries++
	m.bytes += 1024
	return address, nil
}

// MappingLease pins the original domain/address association through final I/O.
type MappingLease struct {
	mapping *Map
	entry   *mapEntry
	once    sync.Once
	closed  atomic.Bool
}

// Borrow rejects missing, expired-unreferenced or retired mappings.
func (m *Map) Borrow(address netip.Addr, now time.Time) (*MappingLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("loft.vpn.privacy_retired")
	}
	entry := m.byIP[address]
	if entry == nil || entry.refs == 0 && !now.Before(entry.expires) {
		return nil, errors.New("loft.vpn.dns_mapping_missing")
	}
	entry.refs++
	return &MappingLease{mapping: m, entry: entry}, nil
}

func (l *MappingLease) Host() string {
	l.mapping.mu.Lock()
	defer l.mapping.mu.Unlock()
	return l.entry.host
}
func (l *MappingLease) Address() netip.Addr { return l.entry.address }

// HoldAdvertisementUntil conservatively starts the advertised TTL at the final
// possible DNS reply I/O. A retired map stays retired; its live lease only keeps
// the address quarantined. It cannot reauthorize lookup or restore proof.
func (l *MappingLease) HoldAdvertisementUntil(now time.Time) {
	if l == nil {
		return
	}
	m := l.mapping
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.closed.Load() {
		return
	}
	deadline := now.Add(time.Duration(m.policy.DNSTTLSeconds) * time.Second)
	if deadline.After(l.entry.expires) {
		l.entry.expires = deadline
	}
}

// Close releases exactly one borrower; retired bytes wait for the final one.
func (l *MappingLease) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.closed.Store(true)
		m := l.mapping
		m.mu.Lock()
		defer m.mu.Unlock()
		l.entry.refs--
		if l.entry.refs == 0 && !l.entry.cached {
			m.release(l.entry)
		}
	})
}

// Close retires the map immediately without disposing active borrowers.
func (m *Map) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	for _, entry := range m.byName {
		entry.cached = false
		if entry.refs == 0 {
			m.release(entry)
		}
	}
	m.byName, m.byIP = nil, nil
}

func (m *Map) Usage() (int, int64) { m.mu.Lock(); defer m.mu.Unlock(); return m.entries, m.bytes }

func (m *Map) expire(now time.Time) {
	for name, entry := range m.byName {
		if !now.Before(entry.expires) && entry.refs == 0 {
			delete(m.byName, name)
			delete(m.byIP, entry.address)
			entry.cached = false
			m.release(entry)
		}
	}
}

func (m *Map) release(entry *mapEntry) {
	processPool.release(entry.address, entry.expires)
	entry.host = ""
	m.entries--
	m.bytes -= 1024
	m.budget.ReleasePacket(1024)
}

func canonicalDomain(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	label := 0
	for index := range host {
		character := host[index]
		if character == '.' {
			if label == 0 || label > 63 {
				return false
			}
			label = 0
			continue
		}
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
		label++
	}
	return label > 0 && label <= 63
}

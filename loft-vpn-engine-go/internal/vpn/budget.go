package vpn

import (
	"errors"
	"sync"
)

// ByteBudget owns the added mobile data-memory ledger.
type ByteBudget struct {
	mu          sync.Mutex
	limit, used int64
}

// ByteLease owns one admitted allocation until its final release.
type ByteLease struct {
	budget *ByteBudget
	bytes  int64
	once   sync.Once
}

// NewBudget constructs a finite global added-data budget.
func NewBudget(limit int64) *ByteBudget { return &ByteBudget{limit: limit} }

// Acquire reserves bytes before allocation/copy.
func (b *ByteBudget) Acquire(bytes int64) (*ByteLease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bytes < 0 || bytes > b.limit-b.used {
		return nil, errors.New("loft.vpn.byte_limit")
	}
	b.used += bytes
	return &ByteLease{budget: b, bytes: bytes}, nil
}

// Used returns current owned bytes.
func (b *ByteBudget) Used() int64 { b.mu.Lock(); defer b.mu.Unlock(); return b.used }

// Close releases an allocation exactly once.
func (l *ByteLease) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() { l.budget.ReleasePacket(int(l.bytes)) })
}

// ReservePacket admits a rounded packet allocation in the shared queue ledger.
func (b *ByteBudget) ReservePacket(bytes int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bytes < 0 || int64(bytes) > b.limit-b.used {
		return false
	}
	b.used += int64(bytes)
	return true
}

// ReleasePacket returns bytes after copy/dequeue, drop or close.
func (b *ByteBudget) ReleasePacket(bytes int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if bytes < 0 || int64(bytes) > b.used {
		panic("loft.vpn.invalid_internal_byte_release")
	}
	b.used -= int64(bytes)
}

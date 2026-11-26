package vpn

import (
	"sync"
	"testing"
)

// Every owned relay/queue allocation must be admitted before copying data;
// aggregate admission cannot be approximated with per-flow default buffers.
func TestByteBudgetRejectsOverflowAndReturnsEachOwnerOnce(t *testing.T) {
	budget := NewBudget(8388608)
	lease, err := budget.Acquire(8388608)
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := budget.Acquire(1); err == nil || owner != nil {
		t.Fatal("aggregate queue overflow admitted")
	}
	var callers sync.WaitGroup
	for i := 0; i < 64; i++ {
		callers.Add(1)
		go func() { defer callers.Done(); lease.Close() }()
	}
	callers.Wait()
	if budget.Used() != 0 {
		t.Fatal("owner leaked or returned bytes twice")
	}
	if lease, err := budget.Acquire(8388608); err != nil {
		t.Fatal("released bytes not reusable")
	} else {
		lease.Close()
	}
}

// Simultaneous producers must share the same byte ledger, including objects
// still in construction or awaiting a writer.
func TestConcurrentByteAdmissionCannotExceedGlobalBudget(t *testing.T) {
	budget := NewBudget(8388608)
	start := make(chan struct{})
	owners := make(chan *ByteLease, 64)
	var callers sync.WaitGroup
	for i := 0; i < 64; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			owner, err := budget.Acquire(262144)
			if err == nil {
				owners <- owner
			}
		}()
	}
	close(start)
	callers.Wait()
	close(owners)
	if len(owners) != 32 || budget.Used() != 8388608 {
		t.Fatal("concurrent allocation escaped aggregate byte admission")
	}
	for owner := range owners {
		owner.Close()
	}
	if budget.Used() != 0 {
		t.Fatal("completed producers left bytes owned")
	}
}

func TestInvalidByteAdmissionDoesNotChangeQueueBudget(t *testing.T) {
	budget := NewBudget(8388608)
	for _, bytes := range []int64{-1, 8388609, 9223372036854775807} {
		if owner, err := budget.Acquire(bytes); err == nil || owner != nil {
			t.Fatal("invalid byte reservation accepted")
		}
	}
	if budget.Used() != 0 {
		t.Fatal("invalid allocation mutated budget")
	}
}

package engine

import (
	"testing"
	"time"
)

func waitForRuntimeState(t *testing.T, runtime *Runtime, want string) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if snapshotForTest(t, runtime).State == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("runtime did not enter %q", want)
		case <-ticker.C:
		}
	}
}

func awaitDrain(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("drain owner did not return after release/cancellation")
		return nil
	}
}

// Treating Close as Drain would cancel the existing owner before it can finish;
// failing to gate admission would allow the runtime to remain busy forever.
func TestDrainGatesNewAdmissionAndWaitsForExistingOwner(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	owner := admitForTest(t, runtime, 100, 30000)
	result := make(chan error, 1)
	go func() { result <- runtime.Drain(5000) }()
	waitForRuntimeState(t, runtime, "draining")
	if owner.Canceled() {
		t.Fatal("drain prematurely canceled an existing owner")
	}
	operation, err := runtime.Admit(1, 100)
	if operation != nil {
		t.Fatal("draining runtime admitted new work")
	}
	requireEngineError(t, err, "loft.engine.draining")
	requireEngineError(t, runtime.Connect(), "loft.engine.draining")
	owner.Close()
	if err := awaitDrain(t, result); err != nil {
		t.Fatalf("released owner did not complete drain: %v", err)
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.State != "drained" || snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("drain did not reach an empty frozen state: %+v", snapshot)
	}
	_, err = runtime.Admit(1, 100)
	requireEngineError(t, err, "loft.engine.drained")
	if err := runtime.Drain(100); err != nil {
		t.Fatalf("repeat completed drain is not idempotent: %v", err)
	}
	runtime.Stop()
	admitForTest(t, runtime, 1, 100)
}

// An uncapped drain wait can retain reservations indefinitely; timeout must
// force cancellation and keep new admission frozen until explicit reset.
func TestDrainDeadlineAbortsRemainingOwners(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	owner := admitForTest(t, runtime, 8388608, 30000)
	result := make(chan error, 1)
	go func() { result <- runtime.Drain(20) }()
	requireEngineError(t, awaitDrain(t, result), "loft.engine.drain_timeout")
	if !owner.Canceled() || owner.Cause() != "loft.engine.drain_timeout" {
		t.Fatalf("drain deadline did not cancel owned work: %q", owner.Cause())
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.State != "blocked" || snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("drain timeout left admitted resources: %+v", snapshot)
	}
	_, err := runtime.Admit(1, 100)
	requireEngineError(t, err, "loft.engine.blocked")
	runtime.Stop()
	admitForTest(t, runtime, 8388608, 100)
}

// Allowing more than one Drain owner creates an unbounded set of timers and
// conflicting completion callbacks for a single runtime generation.
func TestOnlyOneDrainOwnerCanWait(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	owner := admitForTest(t, runtime, 1, 30000)
	result := make(chan error, 1)
	go func() { result <- runtime.Drain(5000) }()
	waitForRuntimeState(t, runtime, "draining")
	requireEngineError(t, runtime.Drain(100), "loft.engine.draining")
	owner.Close()
	if err := awaitDrain(t, result); err != nil {
		t.Fatalf("first drain owner lost completion: %v", err)
	}
}

// Missing deadline validation can turn a negative duration into an immediate
// abort or allow an unbounded blocking control call.
func TestInvalidDrainDeadlinePreservesActiveOwners(t *testing.T) {
	for _, deadline := range []int64{-1, 0, 5001, 9223372036854775807} {
		runtime := NewRuntime()
		owner := admitForTest(t, runtime, 100, 30000)
		requireEngineError(t, runtime.Drain(deadline), "loft.engine.invalid_timeout")
		if owner.Canceled() {
			t.Fatal("invalid drain deadline canceled an owner")
		}
		if snapshot := snapshotForTest(t, runtime); snapshot.State != "open" || snapshot.Operations != 1 || snapshot.Bytes != 100 {
			t.Fatalf("invalid deadline changed runtime ownership: %+v", snapshot)
		}
		runtime.Close()
	}
}

// Abort must perform both admission gating and cancellation. Canceling only
// existing contexts would permit new work while the runtime is blocked.
func TestAbortCancelsOwnersAndKeepsAdmissionFrozen(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	owner := admitForTest(t, runtime, 100, 30000)
	runtime.Abort()
	runtime.Abort()
	if !owner.Canceled() || owner.Cause() != "loft.engine.aborted" {
		t.Fatalf("abort did not cancel its owner: %q", owner.Cause())
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.State != "blocked" || snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("abort did not freeze empty admission: %+v", snapshot)
	}
	_, err := runtime.Admit(1, 100)
	requireEngineError(t, err, "loft.engine.blocked")
	requireEngineError(t, runtime.Connect(), "loft.engine.blocked")
	requireEngineError(t, runtime.Drain(100), "loft.engine.blocked")
	runtime.Stop()
	admitForTest(t, runtime, 1, 100)
}

// Lifecycle cancellation must wake the actual Drain waiter and identify the
// interrupting action, rather than wait for a five-second deadline.
func TestCloseAbortAndStopInterruptOwnedDrain(t *testing.T) {
	for _, test := range []struct {
		name, want string
		action     func(*Runtime)
	}{
		{"close", "loft.engine.closed", (*Runtime).Close},
		{"abort", "loft.engine.aborted", (*Runtime).Abort},
		{"stop", "loft.engine.stopped", (*Runtime).Stop},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := NewRuntime()
			t.Cleanup(runtime.Close)
			owner := admitForTest(t, runtime, 100, 30000)
			result := make(chan error, 1)
			go func() { result <- runtime.Drain(5000) }()
			waitForRuntimeState(t, runtime, "draining")
			test.action(runtime)
			requireEngineError(t, awaitDrain(t, result), test.want)
			if !owner.Canceled() {
				t.Fatal("drain interrupt did not cancel existing owner")
			}
			if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 0 || snapshot.Bytes != 0 {
				t.Fatalf("drain interrupt retained capacity: %+v", snapshot)
			}
		})
	}
}

// An old drain deadline must never abort a fresh generation admitted after
// Stop. This is an actual waiter/generation race, not a timer-based connection.
func TestStoppedDrainCannotCancelFreshGeneration(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	admitForTest(t, runtime, 100, 30000)
	result := make(chan error, 1)
	go func() { result <- runtime.Drain(5000) }()
	waitForRuntimeState(t, runtime, "draining")
	runtime.Stop()
	fresh := admitForTest(t, runtime, 8388608, 30000)
	requireEngineError(t, awaitDrain(t, result), "loft.engine.stopped")
	if fresh.Canceled() {
		t.Fatal("old drain owner canceled fresh generation")
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.State != "open" || snapshot.Operations != 1 || snapshot.Bytes != 8388608 {
		t.Fatalf("old drain modified fresh generation: %+v", snapshot)
	}
}

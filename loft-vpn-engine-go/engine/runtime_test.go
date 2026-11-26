package engine

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

type observedSnapshot struct {
	SchemaVersion  int    `json:"schema_version"`
	TransportReady bool   `json:"transport_ready"`
	State          string `json:"runtime_state"`
	Generation     int64  `json:"generation"`
	Operations     int    `json:"active_operations"`
	Bytes          int64  `json:"reserved_bytes"`
}

func snapshotForTest(t *testing.T, runtime *Runtime) observedSnapshot {
	t.Helper()
	raw := runtime.Snapshot()
	if len(raw) > 65536 {
		t.Fatalf("snapshot exceeds IPC response limit: %d", len(raw))
	}
	var snapshot observedSnapshot
	if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
		t.Fatalf("invalid snapshot JSON: %v", err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.TransportReady || runtime.TransportReady() {
		t.Fatalf("invalid schema or fabricated transport readiness: %+v", snapshot)
	}
	return snapshot
}

func requireEngineError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

func admitForTest(t *testing.T, runtime *Runtime, bytes, timeoutMillis int64) *Operation {
	t.Helper()
	operation, err := runtime.Admit(bytes, timeoutMillis)
	if err != nil || operation == nil {
		t.Fatalf("admission failed: %v", err)
	}
	t.Cleanup(operation.Close)
	return operation
}

// Accidentally allowing Connect would produce a successful control receipt
// without a protected socket, protocol implementation or TUN.
func TestConnectAlwaysReturnsDataPlaneUnavailable(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	requireEngineError(t, runtime.Connect(), "loft.engine.data_plane_unavailable")
	snapshot := snapshotForTest(t, runtime)
	if snapshot.Operations != 0 || snapshot.Bytes != 0 || snapshot.State != "open" {
		t.Fatalf("connect changed local ownership: %+v", snapshot)
	}
}

// Removing the slot guard permits unbounded timers and operation contexts,
// including byte-free control tasks. Releasing one owner must restore one slot.
func TestAdmissionEnforcesSlotQuotaAndReusesReleasedSlot(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	operations := make([]*Operation, 0, 64)
	for i := 0; i < 64; i++ {
		operations = append(operations, admitForTest(t, runtime, 0, 30000))
	}
	rejected, err := runtime.Admit(0, 30000)
	if rejected != nil {
		t.Fatal("over-quota admission returned an owner")
	}
	requireEngineError(t, err, "loft.engine.slot_limit")
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 64 || snapshot.Bytes != 0 {
		t.Fatalf("rejection changed reservations: %+v", snapshot)
	}
	operations[0].Close()
	admitForTest(t, runtime, 0, 30000)
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 64 {
		t.Fatalf("released slot was not reused: %+v", snapshot)
	}
}

// A per-operation guard without an aggregate byte guard lets independent owners
// exceed the added-control-byte reservation budget.
func TestAdmissionEnforcesAggregateByteQuotaAtomically(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	full := admitForTest(t, runtime, 8388608, 30000)
	operation, err := runtime.Admit(1, 30000)
	if operation != nil {
		t.Fatal("byte-over-quota admission returned an owner")
	}
	requireEngineError(t, err, "loft.engine.byte_limit")
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 1 || snapshot.Bytes != 8388608 {
		t.Fatalf("rejected byte request mutated ownership: %+v", snapshot)
	}
	full.Close()
	admitForTest(t, runtime, 8388608, 30000)
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 1 || snapshot.Bytes != 8388608 {
		t.Fatalf("bytes not returned to the owner: %+v", snapshot)
	}
}

// Missing signed-value and upper-bound validation can wrap duration arithmetic
// or consume capacity despite a rejected request.
func TestInvalidAdmissionDoesNotReserveResources(t *testing.T) {
	tests := []struct {
		name           string
		bytes, timeout int64
		want           string
	}{
		{"negative bytes", -1, 100, "loft.engine.invalid_byte_budget"},
		{"oversized bytes", 8388609, 100, "loft.engine.invalid_byte_budget"},
		{"maximum signed bytes", 9223372036854775807, 100, "loft.engine.invalid_byte_budget"},
		{"zero deadline", 1, 0, "loft.engine.invalid_timeout"},
		{"negative deadline", 1, -1, "loft.engine.invalid_timeout"},
		{"oversized deadline", 1, 30001, "loft.engine.invalid_timeout"},
		{"maximum signed deadline", 1, 9223372036854775807, "loft.engine.invalid_timeout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := NewRuntime()
			t.Cleanup(runtime.Close)
			operation, err := runtime.Admit(test.bytes, test.timeout)
			if operation != nil {
				t.Fatal("invalid admission returned an owner")
			}
			requireEngineError(t, err, test.want)
			if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 0 || snapshot.Bytes != 0 {
				t.Fatalf("invalid request reserved resources: %+v", snapshot)
			}
		})
	}
}

// An unsynchronized admission check lets simultaneous callers all observe an
// available slot. Keep the admitted owners alive until every caller finishes.
func TestConcurrentAdmissionsRespectSingleRuntimeQuota(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	start := make(chan struct{})
	owners := make(chan *Operation, 128)
	errors := make(chan error, 128)
	var callers sync.WaitGroup
	for i := 0; i < 128; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			operation, err := runtime.Admit(1, 30000)
			if err != nil {
				errors <- err
				return
			}
			owners <- operation
		}()
	}
	close(start)
	callers.Wait()
	close(owners)
	close(errors)
	if len(owners) != 64 || len(errors) != 64 {
		t.Fatalf("admitted %d and rejected %d, want 64 each", len(owners), len(errors))
	}
	for err := range errors {
		requireEngineError(t, err, "loft.engine.slot_limit")
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 64 || snapshot.Bytes != 64 {
		t.Fatalf("parallel admission violated quota: %+v", snapshot)
	}
	for owner := range owners {
		owner.Close()
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("parallel owners did not release capacity: %+v", snapshot)
	}
}

// Cancel and Close may both arrive through lifecycle paths. Each must signal
// a real context and release this reservation exactly once.
func TestConcurrentCancelAndCloseReturnReservationOnce(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	operation := admitForTest(t, runtime, 8388608, 30000)
	var callers sync.WaitGroup
	for i := 0; i < 64; i++ {
		callers.Add(2)
		go func() { defer callers.Done(); operation.Cancel() }()
		go func() { defer callers.Done(); operation.Close() }()
	}
	callers.Wait()
	if !operation.Canceled() {
		t.Fatal("owner context remains active after close/cancel")
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("double cancellation leaked or double-returned bytes: %+v", snapshot)
	}
	admitForTest(t, runtime, 8388608, 30000)
}

// Forgetting terminal admission gating or canceling outside the reservation
// owner lets Close race with Admit and leave a live operation behind.
func TestRuntimeCloseRacingAdmissionCancelsEveryReturnedOwner(t *testing.T) {
	runtime := NewRuntime()
	start := make(chan struct{})
	owners := make(chan *Operation, 128)
	errors := make(chan error, 128)
	var callers sync.WaitGroup
	for i := 0; i < 128; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			operation, err := runtime.Admit(1024, 30000)
			if err != nil {
				errors <- err
				return
			}
			owners <- operation
		}()
	}
	callers.Add(1)
	go func() { defer callers.Done(); <-start; runtime.Close() }()
	close(start)
	callers.Wait()
	close(owners)
	close(errors)
	for err := range errors {
		if err.Error() != "loft.engine.closed" && err.Error() != "loft.engine.slot_limit" {
			t.Errorf("unexpected racing admission error: %v", err)
		}
	}
	for owner := range owners {
		if !owner.Canceled() {
			t.Errorf("close left admitted operation alive")
		}
		owner.Close()
	}
	runtime.Close()
	if snapshot := snapshotForTest(t, runtime); snapshot.State != "closed" || snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("close is not terminal with returned capacity: %+v", snapshot)
	}
	operation, err := runtime.Admit(1, 100)
	if operation != nil {
		t.Fatal("closed runtime admitted a new owner")
	}
	requireEngineError(t, err, "loft.engine.closed")
	requireEngineError(t, runtime.Connect(), "loft.engine.closed")
}

// A late callback from the stopped generation must never release a reservation
// in the new control generation.
func TestStopCancelsOldGenerationWithoutReleasingNewOwners(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	old := admitForTest(t, runtime, 8388608, 30000)
	before := snapshotForTest(t, runtime)
	runtime.Stop()
	if !old.Canceled() || old.Cause() != "loft.engine.stopped" {
		t.Fatalf("stop did not cancel old owner: %q", old.Cause())
	}
	fresh := admitForTest(t, runtime, 8388608, 30000)
	after := snapshotForTest(t, runtime)
	if after.Generation != before.Generation+1 || old.Generation() == fresh.Generation() {
		t.Fatalf("stop did not advance owned control generation: %+v -> %+v", before, after)
	}
	var callbacks sync.WaitGroup
	for i := 0; i < 64; i++ {
		callbacks.Add(1)
		go func() { defer callbacks.Done(); old.Close(); old.Cancel() }()
	}
	callbacks.Wait()
	if fresh.Canceled() {
		t.Fatal("late old callback canceled fresh owner")
	}
	_, err := runtime.Admit(1, 100)
	requireEngineError(t, err, "loft.engine.byte_limit")
	fresh.Close()
	runtime.Stop()
	runtime.Stop()
	if snapshot := snapshotForTest(t, runtime); snapshot.Generation != after.Generation || snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("idle repeated stop changed ownership: %+v", snapshot)
	}
}

// Generated Java bindings can construct exported Go structs directly. Their
// zero value must enforce the same admission ownership instead of panicking.
func TestZeroValueRuntimeOwnsAndClosesAdmittedOperation(t *testing.T) {
	var runtime Runtime
	operation := admitForTest(t, &runtime, 1, 100)
	runtime.Close()
	if !operation.Canceled() || operation.Cause() != "loft.engine.closed" {
		t.Fatalf("zero-value runtime did not close its owner: %q", operation.Cause())
	}
	requireEngineError(t, runtime.Connect(), "loft.engine.closed")
	var unadmitted Operation
	unadmitted.Close()
	unadmitted.Cancel()
	if !unadmitted.Canceled() || unadmitted.Cause() != "loft.engine.invalid_operation" {
		t.Fatal("unadmitted wrapper object appears to be a live reservation")
	}
}

// Replacing cancellation with bookkeeping would leave actual dependent workers
// running even though the snapshot says the slot was returned.
func TestOperationCancelSignalsRealWaitingWorker(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	operation := admitForTest(t, runtime, 4096, 30000)
	workerDone := make(chan error, 1)
	go func() { <-operation.ctx.Done(); workerDone <- context.Cause(operation.ctx) }()
	operation.Cancel()
	select {
	case err := <-workerDone:
		requireEngineError(t, err, "loft.engine.canceled")
	case <-time.After(2 * time.Second):
		t.Fatal("real worker was not canceled")
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("canceled worker reservation remains owned: %+v", snapshot)
	}
}

// Removing the owned timer lets a forgotten caller retain a slot indefinitely.
func TestOperationDeadlineCancelsAndReturnsResources(t *testing.T) {
	runtime := NewRuntime()
	t.Cleanup(runtime.Close)
	operation := admitForTest(t, runtime, 4096, 10)
	select {
	case <-operation.ctx.Done():
		requireEngineError(t, context.Cause(operation.ctx), "loft.engine.deadline_exceeded")
	case <-time.After(2 * time.Second):
		t.Fatal("operation deadline failed to cancel owned work")
	}
	if snapshot := snapshotForTest(t, runtime); snapshot.Operations != 0 || snapshot.Bytes != 0 {
		t.Fatalf("deadline did not return reservation: %+v", snapshot)
	}
	admitForTest(t, runtime, 8388608, 100)
}

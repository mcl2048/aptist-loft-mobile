package engine

import (
	"context"
	"math"
	"sync"
	"time"
)

type engineError string

func (e engineError) Error() string { return string(e) }

const (
	errUnavailable       engineError = "loft.engine.data_plane_unavailable"
	errClosed            engineError = "loft.engine.closed"
	errSlotLimit         engineError = "loft.engine.slot_limit"
	errByteLimit         engineError = "loft.engine.byte_limit"
	errInvalidByteBudget engineError = "loft.engine.invalid_byte_budget"
	errInvalidTimeout    engineError = "loft.engine.invalid_timeout"
	errCanceled          engineError = "loft.engine.canceled"
	errReleased          engineError = "loft.engine.released"
	errStopped           engineError = "loft.engine.stopped"
	errDeadline          engineError = "loft.engine.deadline_exceeded"
	errInvalidOperation  engineError = "loft.engine.invalid_operation"
	errCounterExhausted  engineError = "loft.engine.counter_exhausted"
	errDraining          engineError = "loft.engine.draining"
	errDrained           engineError = "loft.engine.drained"
	errBlocked           engineError = "loft.engine.blocked"
	errAborted           engineError = "loft.engine.aborted"
	errDrainTimeout      engineError = "loft.engine.drain_timeout"
)

// Runtime owns local control reservations; it does not implement a VPN.
// The zero value is usable for generated wrappers, but NewRuntime is preferred.
// One mutex owns admission, cancellation, generation and all byte accounting.
type Runtime struct {
	mu            sync.Mutex
	state         string
	generation    int64
	nextID        int64
	operations    map[int64]*Operation
	reservedBytes int64
	ctx           context.Context
	cancel        context.CancelCauseFunc
	idle          chan struct{}
}

// Operation owns one finite local control reservation.
// Context and timer ownership never cross gomobile. Closing an unadmitted zero
// value is harmless and cannot manufacture a reservation.
type Operation struct {
	owner      *Runtime
	id         int64
	generation int64
	bytes      int64
	ctx        context.Context
	cancel     context.CancelCauseFunc
	timer      *time.Timer
}

// NewRuntime creates local control state without starting network activity.
func NewRuntime() *Runtime { return &Runtime{} }

func (r *Runtime) initLocked() {
	if r.state != "" {
		return
	}
	r.state = "open"
	r.generation = 1
	r.operations = make(map[int64]*Operation)
	r.ctx, r.cancel = context.WithCancelCause(context.Background())
	r.idle = make(chan struct{})
	close(r.idle)
}

// Snapshot returns immutable, bounded resource metadata.
func (r *Runtime) Snapshot() string {
	r.mu.Lock()
	r.initLocked()
	snapshot := struct {
		SchemaVersion  int           `json:"schema_version"`
		EngineVersion  string        `json:"engine_version"`
		TransportReady bool          `json:"transport_ready"`
		State          string        `json:"runtime_state"`
		Generation     int64         `json:"generation"`
		Operations     int           `json:"active_operations"`
		ReservedBytes  int64         `json:"reserved_bytes"`
		Limits         controlLimits `json:"limits"`
	}{
		SchemaVersion: schemaVersion,
		EngineVersion: engineVersion,
		State:         r.state,
		Generation:    r.generation,
		Operations:    len(r.operations),
		ReservedBytes: r.reservedBytes,
		Limits:        limits(),
	}
	r.mu.Unlock()
	return descriptionJSON(snapshot)
}

// TransportReady reports whether the actual data plane is available.
func (r *Runtime) TransportReady() bool { return false }

// Connect requests the data plane; this framework has no data plane.
func (r *Runtime) Connect() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	if err := r.admissionErrorLocked(); err != nil {
		return err
	}
	return errUnavailable
}

// Admit reserves a byte budget and operation slot until release or deadline.
// Byte budgets are accounting reservations, not allocated data-plane buffers.
// No task is launched. Each explicitly admitted owner has a finite timer and
// context, both canceled by its final owner. Invalid requests are atomic.
func (r *Runtime) Admit(byteBudget, timeoutMillis int64) (*Operation, error) {
	if byteBudget < 0 || byteBudget > maxReservedBytes {
		return nil, errInvalidByteBudget
	}
	if timeoutMillis <= 0 || timeoutMillis > maxOperationMillis {
		return nil, errInvalidTimeout
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	if err := r.admissionErrorLocked(); err != nil {
		return nil, err
	}
	if len(r.operations) >= maxOperations {
		return nil, errSlotLimit
	}
	// Subtraction avoids adding untrusted signed values before validating the
	// aggregate budget. Both operands are already in [0, maxReservedBytes].
	if byteBudget > maxReservedBytes-r.reservedBytes {
		return nil, errByteLimit
	}
	if r.nextID == math.MaxInt64 {
		return nil, errCounterExhausted
	}
	r.nextID++
	ctx, cancel := context.WithCancelCause(r.ctx)
	operation := &Operation{
		owner: r, id: r.nextID, generation: r.generation, bytes: byteBudget,
		ctx: ctx, cancel: cancel,
	}
	if len(r.operations) == 0 {
		r.idle = make(chan struct{})
	}
	r.operations[operation.id] = operation
	r.reservedBytes += byteBudget
	operation.timer = time.AfterFunc(time.Duration(timeoutMillis)*time.Millisecond, func() {
		operation.finish(errDeadline)
	})
	return operation, nil
}

// Stop cancels owned control work while preserving the local runtime object.
// A fresh control generation may admit operations afterwards. This is a local
// lifetime operation, not an engine/TUN/physical-FD completion receipt.
func (r *Runtime) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	if r.state == "closed" || (r.state == "open" && len(r.operations) == 0) {
		return
	}
	r.cancelAllLocked(errStopped)
	if r.generation == math.MaxInt64 {
		r.state = "closed"
		return
	}
	r.generation++
	r.state = "open"
	r.ctx, r.cancel = context.WithCancelCause(context.Background())
}

// Close terminates admission and releases all local control owners.
func (r *Runtime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	if r.state == "closed" {
		return
	}
	r.state = "closed"
	r.cancelAllLocked(errClosed)
}

// Drain freezes admission and waits for existing local control owners.
// Only control reservations are affected, not a VPN transport or TUN.
// Exactly one drain waiter/timer is admitted. Releasing existing operations
// completes the drain; deadline expiry cancels remaining owners and blocks
// admission. Stop, Abort and Close wake the waiter through the owned context.
func (r *Runtime) Drain(timeoutMillis int64) error {
	if timeoutMillis <= 0 || timeoutMillis > maxDrainMillis {
		return errInvalidTimeout
	}
	r.mu.Lock()
	r.initLocked()
	if r.state == "drained" {
		r.mu.Unlock()
		return nil
	}
	if err := r.admissionErrorLocked(); err != nil {
		r.mu.Unlock()
		return err
	}
	r.state = "draining"
	generation, idle, ctx := r.generation, r.idle, r.ctx
	r.mu.Unlock()

	timer := time.NewTimer(time.Duration(timeoutMillis) * time.Millisecond)
	defer timer.Stop()
	timedOut := false
	select {
	case <-idle:
	case <-ctx.Done():
	case <-timer.C:
		timedOut = true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == "closed" {
		return errClosed
	}
	// A previous drain must neither gate nor cancel a newly admitted generation.
	if r.generation != generation {
		return errStopped
	}
	if r.state == "blocked" {
		return errAborted
	}
	if timedOut && len(r.operations) != 0 {
		r.state = "blocked"
		r.cancelAllLocked(errDrainTimeout)
		return errDrainTimeout
	}
	r.state = "drained"
	return nil
}

// Abort freezes local admission and cancels existing control owners.
// The control gate stays blocked until Stop explicitly resets its generation.
// This method does not establish TUN retention or physical-pool shutdown.
func (r *Runtime) Abort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initLocked()
	if r.state == "closed" || r.state == "blocked" {
		return
	}
	r.state = "blocked"
	r.cancelAllLocked(errAborted)
}

func (r *Runtime) admissionErrorLocked() error {
	switch r.state {
	case "open":
		return nil
	case "draining":
		return errDraining
	case "drained":
		return errDrained
	case "blocked":
		return errBlocked
	default:
		return errClosed
	}
}

func (r *Runtime) cancelAllLocked(cause engineError) {
	r.cancel(cause)
	for _, operation := range r.operations {
		r.finishLocked(operation, cause)
	}
}

func (r *Runtime) finishLocked(operation *Operation, cause engineError) {
	if operation.generation != r.generation || r.operations[operation.id] != operation {
		return
	}
	delete(r.operations, operation.id)
	r.reservedBytes -= operation.bytes
	operation.timer.Stop()
	operation.cancel(cause)
	if len(r.operations) == 0 {
		close(r.idle)
	}
}

func (o *Operation) finish(cause engineError) {
	if o == nil || o.owner == nil {
		return
	}
	o.owner.mu.Lock()
	defer o.owner.mu.Unlock()
	o.owner.finishLocked(o, cause)
}

// Cancel ends an operation and returns its reserved capacity.
func (o *Operation) Cancel() { o.finish(errCanceled) }

// Close releases an operation; repeated close/cancel is harmless.
func (o *Operation) Close() { o.finish(errReleased) }

// Canceled reports that the owned context has ended.
func (o *Operation) Canceled() bool {
	return o == nil || o.ctx == nil || o.ctx.Err() != nil
}

// Cause describes why an operation ended using a redacted stable code.
func (o *Operation) Cause() string {
	if o == nil || o.ctx == nil {
		return errInvalidOperation.Error()
	}
	if cause := context.Cause(o.ctx); cause != nil {
		return cause.Error()
	}
	return ""
}

// Generation identifies the runtime control generation that owns the lease.
func (o *Operation) Generation() int64 {
	if o == nil {
		return 0
	}
	return o.generation
}

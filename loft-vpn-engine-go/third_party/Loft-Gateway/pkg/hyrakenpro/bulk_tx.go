package hyrakenpro

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Ordinary TCP DATA owns at most9 units per session and576 process-wide.
// Each unit permits16KiB copied body, including producer-held and queued work.
// Allocator rounding, metadata, ciphertext, HTTP2/TLS and caller input are extra.
var processTXUnits = make(chan struct{}, 576)

// Records live only in this descriptor. A waiting caller reads completed/state,
// never a separate frame alias; writer/drain clears these references before
// releasing admission. No physical-slot accounting substitutes for this lease.
type bulkTXLease struct {
	session   *session
	records   [3]sendRecord
	units     int
	completed atomic.Int64
	once      sync.Once
}

func (l *bulkTXLease) release() {
	l.once.Do(func() {
		for i := range l.records {
			clear(l.records[i].frame)
			l.records[i] = sendRecord{}
		}
		for range l.units {
			<-processTXUnits
			<-l.session.txUnits
		}
	})
}

// Local then global is the only blocking acquisition order. Additional units
// are tried without waiting, so several producers cannot wait to fill a batch.
func (s *Stream) acquireBulkUnit(q chan struct{}) error {
	for {
		ctx, cancel, changed := s.deadlineContext(true)
		if s.ctx.Err() != nil {
			cancel()
			return net.ErrClosed
		}
		if ctx.Err() != nil {
			err := s.deadlineError(ctx)
			cancel()
			return err
		}
		select {
		case q <- struct{}{}:
			cancel()
			return nil
		case <-changed:
			cancel()
		case <-ctx.Done():
			err := s.deadlineError(ctx)
			cancel()
			return err
		case <-s.done:
			cancel()
			return net.ErrClosed
		case <-s.session.ctx.Done():
			cancel()
			return net.ErrClosed
		}
	}
}

func (s *Stream) tryBulkUnit() bool {
	select {
	case s.session.txUnits <- struct{}{}:
	default:
		return false
	}
	select {
	case processTXUnits <- struct{}{}:
		return true
	default:
		<-s.session.txUnits
		return false
	}
}

func (s *Stream) writeOrdinaryBulk(p []byte, bulk bool) (int, error) {
	written := 0
	for len(p) > 0 {
		if err := s.reserveCredit(maxFrameData); err != nil {
			return written, err
		}
		if err := s.acquireBulkUnit(s.session.txUnits); err != nil {
			s.addCredit(maxFrameData)
			return written, err
		}
		if err := s.acquireBulkUnit(processTXUnits); err != nil {
			<-s.session.txUnits
			s.addCredit(maxFrameData)
			return written, err
		}
		l := &bulkTXLease{session: s.session, units: 1}
		// Keep16KiB writer scheduling for shared physical sessions. The map
		// snapshot takes only session.mu; its callers never hold it while taking
		// a stream writeMu. A concurrent OPEN can affect only this bounded group.
		ceiling := 1
		if s.session.streamCount() == 1 {
			ceiling = 3
		}
		remaining := p
		count, groupBytes := 0, 0
		for {
			chunk := min(len(remaining), maxFrameData)
			// Only the admitted descriptor retains the copied frame backing.
			l.records[count].frame = make([]byte, 5+chunk)
			frame := l.records[count].frame
			frame[0] = frameData
			binary.BigEndian.PutUint32(frame[1:5], s.id)
			copy(frame[5:], remaining[:chunk])
			l.records[count].bulk = bulk || len(remaining) > chunk
			count++
			groupBytes += chunk
			remaining = remaining[chunk:]
			if len(remaining) == 0 || count == ceiling || !s.tryBulkUnit() {
				break
			}
			if !s.tryReserveCredit(maxFrameData) {
				<-processTXUnits
				<-s.session.txUnits
				break
			}
			l.units++
		}
		charge := count * maxFrameData
		req := sendRequest{records: l.records[:count], tx: l, completed: &l.completed, done: make(chan error, 1), state: new(atomic.Uint32), refund: func() { s.addCredit(charge) }}
		err := s.submitRequest(req)
		accepted := int(l.completed.Load())
		written += accepted
		if err != nil {
			return written, err
		}
		if accepted != groupBytes {
			return written, io.ErrShortWrite
		}
		p = remaining
	}
	return written, nil
}

func (s *Stream) publishBulkTX(req sendRequest, ctx context.Context, changed <-chan struct{}) (bool, bool, error) {
	select {
	case s.session.txGate <- struct{}{}:
	case <-changed:
		return false, true, nil
	case <-ctx.Done():
		return false, false, s.deadlineError(ctx)
	case <-s.done:
		return false, false, net.ErrClosed
	case <-s.session.ctx.Done():
		return false, false, net.ErrClosed
	}
	defer func() { <-s.session.txGate }()
	if s.session.txClosed || s.session.ctx.Err() != nil || s.ctx.Err() != nil {
		return false, false, net.ErrClosed
	}
	if ctx.Err() != nil {
		return false, false, s.deadlineError(ctx)
	}
	select {
	case s.session.out <- req:
		return true, false, nil
	case <-changed:
		return false, true, nil
	case <-ctx.Done():
		return false, false, s.deadlineError(ctx)
	case <-s.done:
		return false, false, net.ErrClosed
	case <-s.session.ctx.Done():
		return false, false, net.ErrClosed
	}
}

func (s *session) closeBulkTX() {
	s.txGate <- struct{}{}
	s.txClosed = true
	<-s.txGate
	for {
		select {
		case req := <-s.out:
			if req.tx != nil {
				if req.refund != nil {
					req.refund()
				}
				req.tx.release()
			}
		default:
			return
		}
	}
}

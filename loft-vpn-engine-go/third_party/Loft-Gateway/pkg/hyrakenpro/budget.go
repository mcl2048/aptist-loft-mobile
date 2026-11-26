package hyrakenpro

import (
	"errors"
	"sync/atomic"
)

const (
	processPhysicalLimit = 64
	processRXLimit       = 32 << 20
	sessionRXLimit       = 8 << 20
	streamRXLimit        = 1 << 20
)

var physicalSlots = make(chan struct{}, processPhysicalLimit)
var processRXQueued atomic.Int64

func receiveCharge(payload int) int { return max(payload, maxFrameData) }

func acquirePhysical() error {
	select {
	case physicalSlots <- struct{}{}:
		return nil
	default:
		return errors.New("hyrakenpro: physical connection capacity exhausted")
	}
}

func releasePhysical() { <-physicalSlots }

func reserveBytes(counter *atomic.Int64, n, limit int64) bool {
	for {
		old := counter.Load()
		if old+n > limit {
			return false
		}
		if counter.CompareAndSwap(old, old+n) {
			return true
		}
	}
}

func (s *session) reserveRX(stream *Stream, n int) bool {
	bytes := int64(receiveCharge(n))
	if !reserveBytes(&processRXQueued, bytes, processRXLimit) {
		return false
	}
	if !reserveBytes(&s.rxQueued, bytes, sessionRXLimit) {
		processRXQueued.Add(-bytes)
		return false
	}
	if !reserveBytes(&stream.rxQueued, bytes, streamRXLimit) {
		s.rxQueued.Add(-bytes)
		processRXQueued.Add(-bytes)
		return false
	}
	return true
}

func (s *session) releaseRX(stream *Stream, n int) {
	bytes := int64(receiveCharge(n))
	stream.rxQueued.Add(-bytes)
	s.rxQueued.Add(-bytes)
	processRXQueued.Add(-bytes)
}

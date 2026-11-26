package hyrakenpro

import (
	"encoding/binary"
	"errors"
	"io"
)

// queueWindow returns consumed TCP charges without waiting for reverse I/O.
// The wake carries no credit or stream pointer: repeated Reads only coalesce a
// bounded counter, and the existing session writer remains the sole AEAD owner.
func (s *Stream) queueWindow(n int) {
	if s.ctx.Err() != nil {
		return
	}
	if n > streamRXLimit {
		s.session.abort()
		return
	}
	for {
		old := s.pendingWindow.Load()
		if old > streamRXLimit || uint32(n) > streamRXLimit-old {
			// A conforming sender cannot consume more than its receive window
			// without an emitted grant. Fail closed on synthetic/hostile overflow.
			s.session.abort()
			return
		}
		if s.pendingWindow.CompareAndSwap(old, old+uint32(n)) {
			break
		}
	}
	if s.ctx.Err() != nil {
		// Retirement can race the CAS after clearing its counter.
		s.pendingWindow.Store(0)
		return
	}
	select {
	case s.session.windowReady <- struct{}{}:
	default:
	}
}

// retireWindows runs after stream cancellation. Once the writer claims a WINDOW
// its complete authenticated record belongs to the session, so ordinary stream
// retirement neither changes that record nor aborts other streams on its carrier.
func (s *Stream) retireWindows() {
	s.pendingWindow.Store(0)
}

// tryWindowFIN is used only by full Close while a session-owned WINDOW is still
// writing. Terminal publication is best effort and bounded by the existing out
// queue; explicit CloseWrite keeps its synchronous half-close contract.
func (s *session) tryWindowFIN(id uint32) {
	if s.ctx.Err() != nil {
		return
	}
	frame := make([]byte, 5)
	frame[0] = frameFIN
	binary.BigEndian.PutUint32(frame[1:5], id)
	select {
	case s.out <- sendRequest{frame: frame, done: make(chan error, 1)}:
	default:
		// Never silently lose the terminal FIN and strand a peer's stream slot.
		// Match RESET publication's existing bounded overload fallback, without
		// recursively entering abort while Stream.Close owns writeMu.
		s.cancel()
		_ = s.pc.Close()
	}
}

func (s *session) writeWindowBatch(seq *uint64, workspace *recordWorkspace) error {
	var streams [maxStreams]*Stream
	count := 0
	s.mu.Lock()
	for _, stream := range s.streams {
		if stream.network == "tcp" && count < len(streams) {
			streams[count] = stream
			count++
		}
	}
	s.mu.Unlock()
	// The snapshot owns references, never map entries. Retirement and a later
	// stream with the same id cannot redirect a pending counter to its replacement.
	defer func() {
		for _, stream := range streams[:count] {
			stream.windowInFlight.Store(false)
		}
	}()
	used := 0
	var frame [9]byte
	frame[0] = frameWindow
	for _, stream := range streams[:count] {
		if stream.ctx.Err() != nil || stream.pendingWindow.Load() == 0 {
			continue
		}
		stream.windowInFlight.Store(true)
		// Retirement before ownership may drop credit. After this check, the
		// complete WINDOW belongs to the session even if its stream retires.
		if stream.ctx.Err() != nil {
			stream.windowInFlight.Store(false)
			stream.pendingWindow.Store(0)
			continue
		}
		n := stream.pendingWindow.Swap(0)
		if n == 0 {
			stream.windowInFlight.Store(false)
			continue
		}
		if n > streamRXLimit {
			return errors.New("hyrakenpro: pending WINDOW exceeds receive limit")
		}
		binary.BigEndian.PutUint32(frame[1:5], stream.id)
		binary.BigEndian.PutUint32(frame[5:9], n)
		var err error
		used, err = workspace.appendRecord(s, seq, used, frame[:])
		if err != nil {
			return err
		}
	}
	// Every current stream is visited once. Grants arriving during a swap or
	// physical flush publish another capacity-one wake, so none can be missed.
	for sent := 0; sent < used; {
		n, err := s.pc.Write(workspace.wire[sent:used])
		if n < 0 || n > used-sent {
			return io.ErrShortWrite
		}
		sent += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

package hyrakenpro

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"loft.local/hydra"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Stream is one authenticated TCP byte stream or UDP datagram association.
type Stream struct {
	shaper         *hydra.Shaper
	shapeErr       error
	session        *session
	ctx            context.Context
	cancel         context.CancelFunc
	id             uint32
	network        string
	target         string
	source         string
	rx             chan []byte
	done           chan struct{}
	remoteDone     chan struct{}
	closeOnce      sync.Once
	remoteOnce     sync.Once
	readMu         sync.Mutex
	writeMu        sync.Mutex
	writeClosed    bool
	deadlineMu     sync.Mutex
	readDeadline   time.Time
	writeDeadline  time.Time
	readChanged    chan struct{}
	writeChanged   chan struct{}
	creditMu       sync.Mutex
	sendCredit     int64
	creditChanged  chan struct{}
	partial        []byte
	partialCharge  int
	partialSize    int
	rxMu           sync.Mutex
	rxQueued       atomic.Int64
	pendingWindow  atomic.Uint32 // Fully consumed TCP record charges, at most1MiB.
	windowInFlight atomic.Bool   // Writer owns a WINDOW in the physical record batch.
}

func newStream(s *session, id uint32, network, target, source string) *Stream {
	ctx, cancel := context.WithCancel(s.ctx)
	stream := &Stream{session: s, ctx: ctx, cancel: cancel, id: id, network: network, target: target, source: source, rx: make(chan []byte, streamRXLimit/maxFrameData), done: make(chan struct{}), remoteDone: make(chan struct{}), readChanged: make(chan struct{}), writeChanged: make(chan struct{}), sendCredit: streamRXLimit, creditChanged: make(chan struct{})}
	if network == "tcp" && s.hydraConfig != nil && s.hydraConfig.Enabled {
		var streamID [4]byte
		binary.BigEndian.PutUint32(streamID[:], id)
		seed := domainMAC(s.shapeSeed[:], "hydra-stream", s.carrier, "", streamID[:])
		envelope := 9 + s.keys.send.Overhead()
		if s.carrier == TransportGRPC {
			envelope += 5
		}
		stream.shaper, stream.shapeErr = hydra.NewDynamicV2(*s.hydraConfig, "hyraken-pro/v1/"+s.carrier, seed, hydra.Limits{MaxPayload: maxFrameData, MaxPadding: 255, PaddingBurst: 512, PaddingPerSecond: 256}, hydra.TrafficOptions{Framing: hydra.Framing{Envelope: envelope}, StandalonePaddingMinimum: 64, StandalonePaddingEnvelope: envelope})
	}
	return stream
}

// Network returns tcp or udp.
func (s *Stream) Network() string { return s.network }

// Target is the requested destination and must be checked by the outer router.
func (s *Stream) Target() string { return s.target }

// Source is the server-observed physical HTTP peer, never a client supplied value.
func (s *Stream) Source() string { return s.source }

// Read reads bytes for TCP or exactly one packet for UDP.
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 && s.network == "tcp" {
		return 0, nil
	}
	s.readMu.Lock()
	finalize := false
	credit := 0
	defer func() {
		s.readMu.Unlock()
		// Credit control I/O must run after releasing readMu. Its cancellation can
		// abort the session and reset this stream, both of which join readMu.
		if credit > 0 {
			s.grant(credit)
		}
		if finalize && s.finalizeAfterEOF() {
			s.closeLocal()
		}
	}()
	if s.network == "tcp" {
		n := 0
		for {
			if len(s.partial) == 0 {
				var data []byte
				if n == 0 {
					var err error
					data, err = s.readNext()
					if err != nil {
						if err == io.EOF {
							finalize = true
						}
						return 0, err
					}
				} else {
					// Once useful bytes are available, drain only ready DATA. Do not
					// wait for another record or for the caller's buffer to fill.
					select {
					case data = <-s.rx:
					default:
						return n, nil
					}
				}
				s.partial = data
				s.partialCharge = receiveCharge(len(data))
				s.partialSize = len(data)
			}
			copied := copy(p[n:], s.partial)
			n += copied
			s.partial = s.partial[copied:]
			if len(s.partial) != 0 {
				return n, nil
			}
			s.session.releaseRX(s, s.partialSize)
			credit += s.partialCharge
			s.partialCharge = 0
			s.partialSize = 0
			// Every legal TCP DATA costs16KiB. Stop at the existing maximum
			// WINDOW grant even if concurrent receive work refills this queue.
			if n == len(p) || credit >= streamRXLimit || n == 0 {
				return n, nil
			}
		}
	}
	if len(s.partial) != 0 {
		if s.network != "tcp" && len(p) < len(s.partial) {
			return 0, io.ErrShortBuffer
		}
		n := copy(p, s.partial)
		s.partial = s.partial[n:]
		if len(s.partial) == 0 {
			s.session.releaseRX(s, s.partialSize)
			credit = s.partialCharge
			s.partialCharge = 0
			s.partialSize = 0
		}
		return n, nil
	}
	data, err := s.readNext()
	if err != nil {
		if err == io.EOF {
			finalize = true
		}
		return 0, err
	}
	if len(p) < len(data) {
		s.partial = data
		s.partialCharge = receiveCharge(len(data))
		s.partialSize = len(data)
		return 0, io.ErrShortBuffer
	}
	n := copy(p, data)
	s.session.releaseRX(s, len(data))
	credit = receiveCharge(len(data))
	return n, nil
}

func (s *Stream) readNext() ([]byte, error) {
	for {
		select {
		case data := <-s.rx:
			return data, nil
		default:
		}
		select {
		case <-s.remoteDone:
			// The receive loop queues DATA before closing remoteDone for FIN.
			// Those records may have arrived after the first queue probe.
			select {
			case data := <-s.rx:
				return data, nil
			default:
				return nil, io.EOF
			}
		default:
		}
		ctx, cancel, changed := s.deadlineContext(false)
		select {
		case data := <-s.rx:
			cancel()
			return data, nil
		case <-s.remoteDone:
			cancel()
			continue
		case <-s.done:
			cancel()
			return nil, net.ErrClosed
		case <-s.session.ctx.Done():
			cancel()
			return nil, net.ErrClosed
		case <-changed:
			cancel()
			continue
		case <-ctx.Done():
			err := s.deadlineError(ctx)
			cancel()
			return nil, err
		}
	}
}

// Write sends bytes for TCP or one complete packet for UDP. Empty UDP packets are valid.
func (s *Stream) Write(p []byte) (int, error) {
	if s.network != "tcp" {
		return s.WritePacket(p)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return 0, net.ErrClosed
	}
	select {
	case <-s.done:
		return 0, net.ErrClosed
	default:
	}
	if s.shapeErr != nil {
		return 0, s.shapeErr
	}
	bulkWrite := len(p) >= 8192
	// Ordinary DATA groups only bytes ready in this Write. Admission precedes
	// copying; Hydra retains its independent original 16KiB group geometry.
	if s.shaper == nil {
		return s.writeOrdinaryBulk(p, bulkWrite)
	}
	written := 0
	// A sampled candidate that does not fit is carried once, with its already
	// reserved credit, to the next group. This preserves Hydra's sample sequence
	// and original chosen record sizes without copying another group of DATA.
	pendingChunk, pendingBatch := 0, 0
	defer func() {
		if pendingChunk != 0 {
			s.addCredit(maxFrameData)
		}
	}()
	for len(p) > 0 {
		if pendingChunk == 0 {
			if err := s.reserveCredit(maxFrameData); err != nil {
				return written, err
			}
		}
		records := make([]sendRecord, 0, maxDataBatchRecords)
		groupBytes := 0
		ceiling := maxDataBatchRecords
		remaining := p
		for {
			chunk, batch := pendingChunk, pendingBatch
			pendingChunk, pendingBatch = 0, 0
			if chunk == 0 {
				chunk = min(len(remaining), maxFrameData)
				batch = maxDataBatchRecords
				if s.shaper != nil {
					d := s.shaper.Next(time.Now(), len(remaining))
					chunk = min(chunk, max(1, d.Payload))
					batch = d.Batch
				}
			}
			if len(records) == 0 {
				ceiling = min(maxDataBatchRecords, max(1, batch))
			}
			if groupBytes+chunk > maxDataBatchBytes {
				pendingChunk, pendingBatch = chunk, batch
				break
			}
			frame := make([]byte, 5+chunk)
			frame[0] = frameData
			binary.BigEndian.PutUint32(frame[1:5], s.id)
			copy(frame[5:], remaining[:chunk])
			records = append(records, sendRecord{frame: frame, bulk: bulkWrite || len(remaining) > chunk})
			groupBytes += chunk
			remaining = remaining[chunk:]
			if len(remaining) == 0 || len(records) >= ceiling || groupBytes == maxDataBatchBytes {
				break
			}
			// Do not wait for a complete batch's credit: flush the ready prefix.
			if !s.tryReserveCredit(maxFrameData) {
				break
			}
		}
		completed := new(atomic.Int64)
		charge := len(records) * maxFrameData
		req := sendRequest{records: records, done: make(chan error, 1), state: new(atomic.Uint32), completed: completed, refund: func() { s.addCredit(charge) }}
		err := s.submitRequest(req)
		accepted := int(completed.Load())
		written += accepted
		if err != nil {
			return written, err
		}
		if accepted != groupBytes {
			return written, io.ErrShortWrite
		}
		p = remaining
		// Tokens are consumed only after successful DATA, once per original record.
		// DATA now precedes its group's PAD opportunities, rather than alternating.
		for _, record := range records {
			if err := s.writeHydraPadding(len(record.frame) - 5); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// ReadPacket receives one complete UDP packet; short buffers preserve the packet for retry.
func (s *Stream) ReadPacket(p []byte) (int, error) {
	if s.network == "tcp" {
		return 0, errors.New("hyrakenpro: not a UDP stream")
	}
	return s.Read(p)
}

// WritePacket sends one complete UDP packet, including a zero-byte packet.
func (s *Stream) WritePacket(p []byte) (int, error) {
	if s.network == "tcp" {
		return 0, errors.New("hyrakenpro: not a UDP stream")
	}
	limit := maxPacket
	if s.network == "xudp" {
		limit = MaxXUDPFrame
	}
	if len(p) > limit {
		return 0, errors.New("hyrakenpro: UDP packet too large")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return 0, net.ErrClosed
	}
	select {
	case <-s.done:
		return 0, net.ErrClosed
	default:
	}
	err := s.writeFrame(framePacket, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// CloseWrite sends FIN while keeping the read side available for a reply.
func (s *Stream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return nil
	}
	s.writeClosed = true
	ctx, cancel := context.WithTimeout(s.session.ctx, time.Second)
	defer cancel()
	return s.session.sendFrame(ctx, frameFIN, s.id, nil)
}

func (s *Stream) finalizeAfterEOF() bool {
	s.writeMu.Lock()
	closed := s.writeClosed
	s.writeMu.Unlock()
	return closed
}

func (s *Stream) closeLocal() bool {
	closedNow := false
	s.closeOnce.Do(func() {
		closedNow = true
		s.rxMu.Lock()
		close(s.done)
		s.cancel()
		s.retireWindows()
		for {
			select {
			case data := <-s.rx:
				s.session.releaseRX(s, len(data))
			default:
				goto drained
			}
		}
	drained:
		s.rxMu.Unlock()
		s.readMu.Lock()
		if s.partialCharge != 0 {
			s.session.releaseRX(s, s.partialSize)
			s.partial = nil
			s.partialCharge = 0
			s.partialSize = 0
		}
		s.readMu.Unlock()
		s.session.drop(s.id)
	})
	return closedNow
}

func (s *Stream) writeFrame(typ byte, payload []byte, bulk ...bool) error {
	charge := receiveCharge(len(payload))
	if err := s.reserveCredit(charge); err != nil {
		return err
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = typ
	binary.BigEndian.PutUint32(frame[1:5], s.id)
	copy(frame[5:], payload)
	req := sendRequest{frame: frame, done: make(chan error, 1), state: new(atomic.Uint32), refund: func() { s.addCredit(charge) }}
	if len(bulk) != 0 {
		req.bulk = bulk[0]
	}
	return s.submitRequest(req)
}

// submitRequest owns the group's complete credit reservation until the writer
// atomically takes it. Queued cancellation refunds exactly once in writeLoop.
func (s *Stream) submitRequest(req sendRequest) error {
	queued := false
	defer func() {
		if !queued && req.tx != nil {
			req.tx.release() // Only an unpublished request remains caller-owned.
		}
	}()
	for {
		ctx, cancel, changed := s.deadlineContext(true)
		if !queued {
			if req.tx != nil {
				published, retry, err := s.publishBulkTX(req, ctx, changed)
				cancel()
				if retry {
					continue
				}
				if err != nil {
					if req.refund != nil {
						req.refund()
					}
					return err
				}
				queued = published
			} else {
				select {
				case s.session.out <- req:
					queued = true
				case <-changed:
					cancel()
					continue
				case <-ctx.Done():
					err := s.deadlineError(ctx)
					cancel()
					if req.refund != nil {
						req.refund()
					}
					return err
				case <-s.done:
					cancel()
					if req.refund != nil {
						req.refund()
					}
					return net.ErrClosed
				case <-s.session.ctx.Done():
					cancel()
					if req.refund != nil {
						req.refund()
					}
					return net.ErrClosed
				}
				cancel()
			}
		}
		ctx, cancel, changed = s.deadlineContext(true)
		select {
		case err := <-req.done:
			cancel()
			return err
		case <-changed:
			cancel()
			continue
		case <-ctx.Done():
			err := s.deadlineError(ctx)
			cancel()
			s.session.cancelSend(req)
			return err
		case <-s.done:
			cancel()
			s.session.cancelSend(req)
			return net.ErrClosed
		case <-s.session.ctx.Done():
			cancel()
			return net.ErrClosed
		}
	}
}

func (s *Stream) tryReserveCredit(n int) bool {
	s.creditMu.Lock()
	defer s.creditMu.Unlock()
	if s.sendCredit < int64(n) {
		return false
	}
	s.sendCredit -= int64(n)
	return true
}

func (s *Stream) reserveCredit(n int) error {
	for {
		s.creditMu.Lock()
		if s.sendCredit >= int64(n) {
			s.sendCredit -= int64(n)
			s.creditMu.Unlock()
			return nil
		}
		changed := s.creditChanged
		s.creditMu.Unlock()
		ctx, cancel, deadlineChanged := s.deadlineContext(true)
		select {
		case <-changed:
			cancel()
		case <-deadlineChanged:
			cancel()
		case <-s.done:
			cancel()
			return net.ErrClosed
		case <-s.session.ctx.Done():
			cancel()
			return net.ErrClosed
		case <-ctx.Done():
			err := s.deadlineError(ctx)
			cancel()
			return err
		}
	}
}

func (s *Stream) addCredit(n int) bool {
	s.creditMu.Lock()
	defer s.creditMu.Unlock()
	if s.sendCredit+int64(n) > streamRXLimit {
		return false
	}
	s.sendCredit += int64(n)
	close(s.creditChanged)
	s.creditChanged = make(chan struct{})
	return true
}

func (s *Stream) grant(n int) {
	if n <= 0 {
		return
	}
	if s.network == "tcp" {
		s.queueWindow(n)
		return
	}
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], uint32(n))
	_ = s.session.sendFrame(s.ctx, frameWindow, s.id, payload[:])
}

// Close releases the logical stream and signals end of stream to its peer.
func (s *Stream) Close() error {
	windowOwned := s.windowInFlight.Load()
	_ = s.closeLocal()
	if windowOwned || s.windowInFlight.Load() {
		// Read may already have returned while its credit is physically blocked.
		// Full Close must return promptly and preserve the shared session; an
		// explicit CloseWrite remains the synchronous half-close operation.
		s.writeMu.Lock()
		if !s.writeClosed {
			s.writeClosed = true
			s.session.tryWindowFIN(s.id)
		}
		s.writeMu.Unlock()
		return nil
	}
	_ = s.CloseWrite()
	return nil
}

func (s *Stream) reset(notify bool) {
	s.closeOnce.Do(func() {
		s.rxMu.Lock()
		close(s.done)
		s.cancel()
		s.retireWindows()
		for {
			select {
			case data := <-s.rx:
				s.session.releaseRX(s, len(data))
			default:
				goto drained
			}
		}
	drained:
		s.rxMu.Unlock()
		s.readMu.Lock()
		if s.partialCharge != 0 {
			s.session.releaseRX(s, s.partialSize)
			s.partial = nil
			s.partialCharge = 0
			s.partialSize = 0
		}
		s.readMu.Unlock()
		s.session.drop(s.id)
		if notify {
			req := sendRequest{frame: make([]byte, 5), done: make(chan error, 1)}
			req.frame[0] = frameReset
			binary.BigEndian.PutUint32(req.frame[1:5], s.id)
			select {
			case s.session.out <- req:
			default:
				s.session.cancel()
				_ = s.session.pc.Close()
			}
		}
	})
}

type proAddr struct{ network, value string }

func (a proAddr) Network() string      { return a.network }
func (a proAddr) String() string       { return a.value }
func (s *Stream) LocalAddr() net.Addr  { return proAddr{network: s.network, value: "hyrakenpro"} }
func (s *Stream) RemoteAddr() net.Addr { return proAddr{network: s.network, value: s.target} }

func (s *Stream) SetDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	close(s.readChanged)
	s.readChanged = make(chan struct{})
	close(s.writeChanged)
	s.writeChanged = make(chan struct{})
	s.deadlineMu.Unlock()
	return nil
}
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	close(s.readChanged)
	s.readChanged = make(chan struct{})
	s.deadlineMu.Unlock()
	return nil
}
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = t
	close(s.writeChanged)
	s.writeChanged = make(chan struct{})
	s.deadlineMu.Unlock()
	return nil
}

func (s *Stream) deadlineContext(write bool) (context.Context, context.CancelFunc, <-chan struct{}) {
	s.deadlineMu.Lock()
	deadline := s.readDeadline
	changed := (<-chan struct{})(s.readChanged)
	if write {
		deadline = s.writeDeadline
		changed = s.writeChanged
	}
	s.deadlineMu.Unlock()
	if deadline.IsZero() {
		// Preserve the session lifetime of the original child context. Stream
		// waits observe s.done separately, and releasing a wait has no effect.
		return s.session.ctx, func() {}, changed
	}
	ctx, cancel := context.WithDeadline(s.session.ctx, deadline)
	return ctx, cancel, changed
}

// A net.Conn deadline is a timeout; cancellation of its owner is a close.
func (s *Stream) deadlineError(ctx context.Context) error {
	select {
	case <-s.done:
		return net.ErrClosed
	case <-s.session.ctx.Done():
		return net.ErrClosed
	default:
	}
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) {
		return os.ErrDeadlineExceeded
	}
	return err
}

// writeHydraPadding is called under this stream's writer mutex. Padding consumes
// the same bounded token bucket across all DATA writes; it is authenticated and
// never appears in business reads. Timing sampling remains session-owned.
func (s *Stream) writeHydraPadding(payload int) error {
	if s.shaper == nil {
		return s.shapeErr
	}
	n := s.shaper.NextStandalonePadding(time.Now(), payload)
	if n == 0 {
		return nil
	}
	padding := make([]byte, n)
	if _, e := rand.Read(padding); e != nil {
		return e
	}
	ctx, cancel, _ := s.deadlineContext(true)
	defer cancel()
	return s.session.sendFrame(ctx, framePadding, 0, padding)
}

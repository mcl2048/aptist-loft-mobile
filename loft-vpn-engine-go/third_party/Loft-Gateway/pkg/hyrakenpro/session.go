package hyrakenpro

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"loft.local/hydra"
	"loft.local/trafficprofile"
)

const (
	frameOpen              byte = 1
	frameData              byte = 2
	frameFIN               byte = 3
	framePacket            byte = 4
	frameReset             byte = 5
	framePadding           byte = 6
	frameWindow            byte = 7
	maxRecord                   = MaxXUDPFrame + 5 + 32
	maxRecordsPerDirection      = 1 << 24
	maxDataBatchRecords         = 8
	maxDataBatchBytes           = maxFrameData
	// One existing maximum XUDP record is larger than the bounded DATA group.
	writerWorkspaceBytes = max(maxDataBatchBytes+maxDataBatchRecords*(9+32), maxRecord+4)
)

type cipherPair struct {
	send, recv             cipher.AEAD
	sendPrefix, recvPrefix [8]byte
}

type sendRecord struct {
	frame []byte
	bulk  bool
}

type sendRequest struct {
	records   []sendRecord  // Only already-ready DATA from one synchronous Write.
	completed *atomic.Int64 // Completely accepted DATA bytes, conservative on errors.
	frame     []byte
	done      chan error
	state     *atomic.Uint32
	refund    func()
	bulk      bool         // Original application write has ready bytes beyond this record.
	tx        *bulkTXLease // Non-nil only for bounded ordinary TCP DATA.
}

type sessionOptions struct {
	xudpEnabled   bool
	packetOnly    bool
	hydraObserver func(int, int)
}

type session struct {
	carrier           string
	shapeSeed         [32]byte
	pc                physicalConn
	keys              *cipherPair
	ctx               context.Context
	cancel            context.CancelFunc
	stopParent        func() bool
	wg                sync.WaitGroup
	once              sync.Once
	out               chan sendRequest
	windowReady       chan struct{} // One coalesced wake; credit stays on bounded streams.
	mu                sync.Mutex
	streams           map[uint32]*Stream
	nextID            uint32
	client            bool
	source            string
	accept            chan<- *Stream
	profile           *trafficprofile.Profile
	hydraConfig       *hydra.Config
	hydraObserver     func(int, int)
	idleSince         time.Time
	rxQueued          atomic.Int64
	releasePhysical   func()
	xudpEnabled       bool
	packetOnly        bool
	trafficClassBound bool
	txGate            chan struct{} // Cancellable leased-publication barrier.
	txClosed          bool          // Protected by txGate.
	txUnits           chan struct{} // Includes building, queued and writer-owned DATA.
}

func newSession(parent context.Context, pc physicalConn, keys recordKeys, client bool, source string, accept chan<- *Stream, profile *trafficprofile.Profile, hydraConfig *hydra.Config, carrier string, release func(), options ...sessionOptions) (*session, error) {
	ciphers, err := newCiphers(keys)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &session{carrier: carrier, shapeSeed: keys.send, pc: pc, keys: ciphers, ctx: ctx, cancel: cancel, out: make(chan sendRequest, 8), windowReady: make(chan struct{}, 1), streams: make(map[uint32]*Stream), nextID: 1, client: client, source: source, accept: accept, profile: profile, hydraConfig: hydraConfig, releasePhysical: release, idleSince: time.Now(), txGate: make(chan struct{}, 1), txUnits: make(chan struct{}, 9)}
	if len(options) != 0 {
		s.xudpEnabled, s.packetOnly = options[0].xudpEnabled, options[0].packetOnly
		if hydraConfig != nil && hydraConfig.Enabled {
			s.hydraObserver = options[0].hydraObserver
		}
	}
	s.trafficClassBound = client
	// AfterFunc may start before returning; abort takes mu before reading stopParent.
	s.mu.Lock()
	s.stopParent = context.AfterFunc(parent, s.abort)
	s.mu.Unlock()
	s.wg.Add(2)
	go s.readLoop()
	go s.writeLoop()
	return s, nil
}

func (s *session) abort() {
	s.once.Do(func() {
		s.cancel()
		_ = s.pc.Close()
		s.mu.Lock()
		streams := make([]*Stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		s.mu.Unlock()
		for _, stream := range streams {
			stream.reset(false)
		}
		if s.stopParent != nil {
			s.stopParent()
		}
		if s.releasePhysical != nil {
			s.releasePhysical()
		}
	})
}

func (s *session) Close() error     { s.abort(); s.wg.Wait(); return nil }
func (s *session) active() bool     { return s.ctx.Err() == nil }
func (s *session) streamCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.streams) }
func (s *session) idleFor(now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.streams) != 0 || s.idleSince.IsZero() {
		return 0
	}
	return now.Sub(s.idleSince)
}

func (s *session) open(ctx context.Context, network, target string) (*Stream, error) {
	if network == "xudp" && (!s.xudpEnabled || !s.packetOnly || target != XUDPTarget) {
		return nil, errors.New("hyrakenpro: XUDP requires an explicitly enabled packet session")
	}
	if s.packetOnly && network != "xudp" {
		return nil, errors.New("hyrakenpro: packet session cannot carry TCP or legacy UDP")
	}
	s.mu.Lock()
	if len(s.streams) >= maxStreams || s.nextID > math.MaxUint32-2 {
		s.mu.Unlock()
		return nil, errors.New("hyrakenpro: stream capacity exhausted")
	}
	id := s.nextID
	s.nextID += 2
	stream := newStream(s, id, network, target, "")
	s.streams[id] = stream
	s.idleSince = time.Time{}
	s.mu.Unlock()
	payload := make([]byte, 1+2+len(target))
	if network == "udp" {
		payload[0] = 2
	} else if network == "xudp" {
		payload[0] = 3
	} else {
		payload[0] = 1
	}
	binary.BigEndian.PutUint16(payload[1:3], uint16(len(target)))
	copy(payload[3:], target)
	if err := s.sendFrame(ctx, frameOpen, id, payload); err != nil {
		stream.closeLocal()
		s.tryReset(id)
		return nil, err
	}
	return stream, nil
}

func (s *session) tryReset(id uint32) {
	frame := make([]byte, 5)
	frame[0] = frameReset
	binary.BigEndian.PutUint32(frame[1:5], id)
	select {
	case s.out <- sendRequest{frame: frame, done: make(chan error, 1)}:
	default:
		s.cancel()
		_ = s.pc.Close()
	}
}

func (s *session) drop(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	if len(s.streams) == 0 {
		s.idleSince = time.Now()
	}
	s.mu.Unlock()
}

func (s *session) sendFrame(ctx context.Context, typ byte, id uint32, payload []byte) error {
	frame := make([]byte, 5+len(payload))
	frame[0] = typ
	binary.BigEndian.PutUint32(frame[1:5], id)
	copy(frame[5:], payload)
	req := sendRequest{frame: frame, done: make(chan error, 1), state: new(atomic.Uint32)}
	select {
	case s.out <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return net.ErrClosed
	}
	select {
	case err := <-req.done:
		return err
	case <-ctx.Done():
		s.cancelSend(req)
		return ctx.Err()
	case <-s.ctx.Done():
		return net.ErrClosed
	}
}

// recordWorkspace belongs exclusively to the session writer. The separate AD
// and nonce arrays cannot overlap Seal's output, which occupies wire only.
type recordWorkspace struct {
	wire   [writerWorkspaceBytes]byte
	header [4]byte
	nonce  [16]byte
}

func (w *recordWorkspace) appendRecord(s *session, seq *uint64, used int, frame []byte) (int, error) {
	if *seq >= maxRecordsPerDirection {
		return used, errors.New("hyrakenpro: record limit reached")
	}
	size := s.keys.send.NonceSize()
	copy(w.nonce[:size-8], s.keys.sendPrefix[:size-8])
	binary.BigEndian.PutUint64(w.nonce[size-8:size], *seq)
	n := len(frame) + s.keys.send.Overhead()
	if used+4+n > len(w.wire) {
		return used, errors.New("hyrakenpro: writer workspace exhausted")
	}
	binary.BigEndian.PutUint32(w.header[:], uint32(n))
	copy(w.wire[used:used+4], w.header[:])
	// Plaintext is request-owned and disjoint from the writer-owned destination.
	out := s.keys.send.Seal(w.wire[used+4:used+4], w.nonce[:size], frame, w.header[:])
	*seq++
	return used + 4 + len(out), nil
}

func (s *session) writeLoop() {
	defer s.wg.Done()
	defer func() {
		s.abort() // Wake a publisher blocked on out before joining its gate.
		s.closeBulkTX()
	}()
	var seq uint64
	var workspace recordWorkspace
	var sampler timingSampler
	if s.profile != nil && s.profile.Timing != nil && s.profile.Timing.Enabled {
		var seed [8]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return
		}
		v := newChameleonSampler(*s.profile.Timing, binary.BigEndian.Uint64(seed[:]))
		sampler = &v
	}
	for {
		var req sendRequest
		select {
		case <-s.ctx.Done():
			return
		case <-s.windowReady:
			if err := s.writeWindowBatch(&seq, &workspace); err != nil {
				return
			}
			// Even a continuously replenished WINDOW wake must yield to one
			// queued request before another bounded control batch is written.
			select {
			case <-s.ctx.Done():
				return
			case req = <-s.out:
			default:
				continue
			}
		case req = <-s.out:
			// If both queues were ready, controls receive deterministic priority.
			// Never wait for more credit or collect a second batch before DATA.
			select {
			case <-s.windowReady:
				if err := s.writeWindowBatch(&seq, &workspace); err != nil {
					// This request was removed from out but never transferred to
					// writeRequest; shutdown cannot recover its leased DATA there.
					if req.tx != nil {
						if req.refund != nil {
							req.refund()
						}
						req.tx.release()
					}
					req.done <- err
					return
				}
			default:
			}
		}
		err := s.writeRequest(&seq, &workspace, sampler, req)
		if req.tx != nil {
			req.tx.release() // writeRequest has finished borrowing every frame.
			req.records = nil
		}
		req.done <- err
		if err != nil && (req.state == nil || req.state.Load() != 2 || s.ctx.Err() != nil) {
			return
		}
	}
}

// timingSampler keeps the writer's scheduling policy local to Pro while the
// independent wire fixtures can still pass the unchanged shared sampler.
type timingSampler interface {
	Next(time.Time, int, bool) trafficprofile.Decision
}

func (s *session) writeRequest(seq *uint64, workspace *recordWorkspace, sampler timingSampler, req sendRequest) error {
	owned := false
	used := 0
	var ends [maxDataBatchRecords]int
	var sizes [maxDataBatchRecords]int
	var kinds [maxDataBatchRecords]byte
	count := 0
	flush := func() error {
		if used == 0 {
			return nil
		}
		sent := 0
		for sent < used {
			n, err := s.pc.Write(workspace.wire[sent:used])
			if n < 0 || n > used-sent {
				return io.ErrShortWrite
			}
			sent += n
			for count > 0 && sent >= ends[0] {
				if kinds[0] == frameData {
					if req.completed != nil {
						req.completed.Add(int64(sizes[0]))
					}
					if s.hydraObserver != nil {
						s.hydraObserver(1, 0)
					}
				} else if s.hydraObserver != nil {
					s.hydraObserver(0, sizes[0])
				}
				copy(ends[:], ends[1:count])
				copy(sizes[:], sizes[1:count])
				copy(kinds[:], kinds[1:count])
				count--
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
		used = 0
		count = 0
		return nil
	}
	if req.state != nil && req.state.Load() == 2 {
		if req.refund != nil {
			req.refund()
		}
		return context.DeadlineExceeded
	}
	records := req.records
	if len(records) == 0 {
		records = []sendRecord{{frame: req.frame, bulk: req.bulk}}
	}
	for _, record := range records {
		decision := trafficprofile.Decision{}
		if sampler != nil && record.frame[0] == frameData {
			decision = sampler.Next(time.Now(), len(record.frame)-5, record.bulk || len(s.out) != 0)
			if s.hydraConfig != nil && s.hydraConfig.Enabled {
				decision.Padding = 0
			}
		}
		if decision.Delay > 0 {
			if err := flush(); err != nil {
				return err
			}
			timer := time.NewTimer(decision.Delay)
			select {
			case <-timer.C:
			case <-s.ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return net.ErrClosed
			}
		}
		// Transfer ownership before encryption of the first record; any later
		// cancellation closes the carrier, including at an internal timing boundary.
		if !owned {
			if req.state != nil && !req.state.CompareAndSwap(0, 1) {
				if req.refund != nil {
					req.refund()
				}
				return context.DeadlineExceeded
			}
			owned = true
		}
		var err error
		used, err = workspace.appendRecord(s, seq, used, record.frame)
		if err != nil {
			// A complete prefix remains accepted at a key-usage boundary.
			if flushErr := flush(); flushErr != nil {
				return flushErr
			}
			return err
		}
		kind := record.frame[0]
		if kind == frameData && (req.completed != nil || s.hydraObserver != nil) || kind == framePadding && s.hydraObserver != nil {
			ends[count] = used
			sizes[count] = len(record.frame) - 5
			kinds[count] = kind
			count++
		}
		if decision.Padding > 0 {
			if err := flush(); err != nil {
				return err
			}
			padding := make([]byte, 5+decision.Padding)
			padding[0] = framePadding
			if _, err := rand.Read(padding[5:]); err != nil {
				return err
			}
			used, err = workspace.appendRecord(s, seq, 0, padding)
			if err != nil {
				return err
			}
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// writeRecord retains the original one-record API used by independent wire
// oracles. Production reuses the writer-local workspace in writeRequest.
func (s *session) writeRecord(seq *uint64, frame []byte) error {
	if *seq >= maxRecordsPerDirection {
		return errors.New("hyrakenpro: record limit reached")
	}
	nonce := make([]byte, s.keys.send.NonceSize())
	copy(nonce, s.keys.sendPrefix[:len(nonce)-8])
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], *seq)
	*seq++
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(frame)+s.keys.send.Overhead()))
	ciphertext := s.keys.send.Seal(nil, nonce, frame, header[:])
	packet := append(header[:], ciphertext...)
	return writeFull(s.pc, packet)
}

func (s *session) readLoop() {
	defer s.wg.Done()
	defer s.abort()
	var seq uint64
	var header [4]byte
	var nonce [16]byte
	var ciphertext []byte
	defer func() {
		clear(ciphertext[:cap(ciphertext)])
		clear(nonce[:])
		clear(header[:])
	}()
	size := s.keys.recv.NonceSize()
	copy(nonce[:size-8], s.keys.recvPrefix[:size-8])
	for {
		if seq >= maxRecordsPerDirection {
			return
		}
		if _, err := io.ReadFull(s.pc, header[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(header[:])
		if n < uint32(5+s.keys.recv.Overhead()) || n > maxRecord {
			return
		}
		if int(n) > cap(ciphertext) {
			capacity := min(maxRecord, max(int(n), 2*cap(ciphertext), 4096))
			// The previous plaintext has already been copied into bounded RX ownership.
			// Clear before releasing an old high-water allocation on growth as well.
			clear(ciphertext[:cap(ciphertext)])
			ciphertext = make([]byte, capacity)
		}
		ciphertext = ciphertext[:int(n)]
		if _, err := io.ReadFull(s.pc, ciphertext); err != nil {
			return
		}
		binary.BigEndian.PutUint64(nonce[size-8:size], seq)
		seq++
		frame, err := s.keys.recv.Open(ciphertext[:0], nonce[:size], ciphertext, header[:])
		if err != nil {
			return
		}
		if !s.handleFrame(frame) {
			return
		}
	}
}

func (s *session) handleFrame(frame []byte) bool {
	if len(frame) < 5 {
		return false
	}
	typ := frame[0]
	id := binary.BigEndian.Uint32(frame[1:5])
	payload := frame[5:]
	if typ == framePadding {
		return id == 0 && len(payload) <= 512
	}
	if id == 0 {
		return false
	}
	if typ == frameOpen {
		if s.client || id%2 != 1 || len(payload) < 3 {
			return false
		}
		var network string
		switch payload[0] {
		case 1:
			network = "tcp"
		case 2:
			network = "udp"
		case 3:
			if !s.xudpEnabled {
				return false
			}
			network = "xudp"
		default:
			return false
		}
		length := int(binary.BigEndian.Uint16(payload[1:3]))
		if len(payload) != 3+length {
			return false
		}
		target := string(payload[3:])
		if validateTarget(target) != nil {
			return false
		}
		if network == "xudp" && target != XUDPTarget {
			return false
		}
		s.mu.Lock()
		packetOnly := network == "xudp"
		if s.trafficClassBound && s.packetOnly != packetOnly {
			s.mu.Unlock()
			return false
		}
		s.packetOnly, s.trafficClassBound = packetOnly, true
		if len(s.streams) >= maxStreams || s.streams[id] != nil {
			s.mu.Unlock()
			return false
		}
		stream := newStream(s, id, network, target, s.source)
		s.streams[id] = stream
		s.mu.Unlock()
		select {
		case s.accept <- stream:
			return true
		case <-s.ctx.Done():
			return false
		}
	}
	s.mu.Lock()
	stream := s.streams[id]
	s.mu.Unlock()
	if stream == nil {
		return typ == frameFIN || typ == frameData || typ == framePacket || typ == frameReset || typ == frameWindow
	}
	switch typ {
	case frameData:
		if stream.network != "tcp" || len(payload) > maxFrameData {
			return false
		}
	case framePacket:
		limit := maxPacket
		if stream.network == "xudp" {
			limit = MaxXUDPFrame
		}
		if stream.network == "tcp" || len(payload) > limit {
			return false
		}
	case frameFIN:
		if len(payload) != 0 {
			return false
		}
		stream.remoteOnce.Do(func() { close(stream.remoteDone) })
		return true
	case frameReset:
		if len(payload) != 0 {
			return false
		}
		stream.reset(false)
		return true
	case frameWindow:
		if len(payload) != 4 {
			return false
		}
		n := binary.BigEndian.Uint32(payload)
		return n > 0 && n <= streamRXLimit && stream.addCredit(int(n))
	default:
		return false
	}
	stream.rxMu.Lock()
	select {
	case <-stream.done:
		stream.rxMu.Unlock()
		return true
	default:
	}
	if !s.reserveRX(stream, len(payload)) {
		stream.rxMu.Unlock()
		stream.reset(true)
		return true
	}
	select {
	case stream.rx <- append([]byte(nil), payload...):
		stream.rxMu.Unlock()
		return true
	default:
		s.releaseRX(stream, len(payload))
		stream.rxMu.Unlock()
		stream.reset(true)
		return true
	}
}

// Request states: 0 queued, 1 writer-owned, 2 canceled. Atomically transferring
// ownership prevents a deadline racing the last cancellation check from emitting
// a record after the caller has returned. In-flight cancellation is fail-closed.
func (s *session) cancelSend(req sendRequest) {
	if req.state != nil && req.state.Swap(2) == 1 {
		s.abort()
	}
}

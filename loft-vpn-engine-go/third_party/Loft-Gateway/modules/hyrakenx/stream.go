package hyrakenx

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	"loft.local/hydra"
)

const maxStreamPacket = HeaderSize + MaxDatagramPayload + 2 + 32

// Submit up to eight unchanged records together. This fills QUIC packets
// without a timer, extra worker, wire change or cross-stream payload queue.
const streamWriteBatch = 8 * (2 + maxStreamPacket)

// OpenStream creates a reliable logical connection on the existing UDP socket.
// The OPEN target is authenticated inside the stream's first encrypted record.
func (p *Peer) OpenStream(ctx context.Context, network, target string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hyrakenx: open logical stream: %w", err)
	}
	if network != "tcp" && network != "udp" {
		return nil, errors.New("hyrakenx: unsupported logical network")
	}
	if len(target) == 0 || len(target) > 253 {
		return nil, errors.New("hyrakenx: invalid target length")
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return nil, fmt.Errorf("hyrakenx: invalid target: %w", err)
	}
	config, scope, observer := p.streamHydraPolicy()
	stream, err := p.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("hyrakenx: open logical stream: %w", err)
	}
	session, err := p.session.stream(uint64(stream.StreamID()))
	if err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return nil, err
	}
	c := &streamConn{stream: stream, session: session, local: p.conn.LocalAddr(), remote: p.conn.RemoteAddr(), hydraObserver: observer}
	c.shaper, err = newStreamShaperScoped(config, session, scope)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	open := make([]byte, 3+len(target))
	if network == "tcp" {
		open[0] = 1
	} else {
		open[0] = 2
	}
	binary.BigEndian.PutUint16(open[1:3], uint16(len(target)))
	copy(open[3:], target)
	releaseDeadline := bindOpeningContext(stream, ctx)
	err = c.writeRecord(open)
	releaseDeadline()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

type streamOpeningError struct{ error }

func (e *streamOpeningError) Unwrap() error { return e.error }

// IsStreamOpeningError reports a failure after accepting one QUIC stream.
// That stream is closed; callers may accept another while the peer and their
// context remain live. Errors accepting from the connection are not included.
func IsStreamOpeningError(err error) bool {
	var openingError *streamOpeningError
	return errors.As(err, &openingError)
}

// AcceptStream validates the encrypted OPEN before returning a stream to the
// gateway router. No destination is dialed by this package.
func (p *Peer) AcceptStream(ctx context.Context) (_ net.Conn, _ string, _ string, err error) {
	if err := ctx.Err(); err != nil {
		return nil, "", "", fmt.Errorf("hyrakenx: accept logical stream: %w", err)
	}
	config, scope, observer := p.streamHydraPolicy()
	stream, err := p.conn.AcceptStream(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("hyrakenx: accept logical stream: %w", err)
	}
	defer func() {
		if err != nil {
			err = &streamOpeningError{err}
		}
	}()
	session, err := p.session.stream(uint64(stream.StreamID()))
	if err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return nil, "", "", err
	}
	c := &streamConn{stream: stream, session: session, local: p.conn.LocalAddr(), remote: p.conn.RemoteAddr(), hydraObserver: observer}
	c.shaper, err = newStreamShaperScoped(config, session, scope)
	if err != nil {
		_ = c.Close()
		return nil, "", "", err
	}
	releaseDeadline := bindOpeningContext(stream, ctx)
	open, err := c.readRecord()
	releaseDeadline()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = c.Close()
		return nil, "", "", err
	}
	if len(open) < 4 || len(open)-3 > 253 || int(binary.BigEndian.Uint16(open[1:3])) != len(open)-3 {
		_ = c.Close()
		return nil, "", "", errors.New("hyrakenx: malformed OPEN record")
	}
	var network string
	switch open[0] {
	case 1:
		network = "tcp"
	case 2:
		network = "udp"
	default:
		_ = c.Close()
		return nil, "", "", errors.New("hyrakenx: invalid OPEN network")
	}
	target := string(open[3:])
	if _, _, err := net.SplitHostPort(target); err != nil {
		_ = c.Close()
		return nil, "", "", fmt.Errorf("hyrakenx: malformed OPEN target: %w", err)
	}
	return c, network, target, nil
}

// streamConn frames independent AEAD records on a QUIC reliable stream.
// Concurrent Read and Write are allowed; each direction has its own lock.
type streamConn struct {
	stream              *quic.Stream
	session             *Session
	local, remote       net.Addr
	readMu, writeMu     sync.Mutex
	shaper              *hydra.Shaper // Owned by writeMu; OPEN bypasses shaping.
	hydraObserver       func(int, int)
	pending             []byte
	readErr             error       // Owned by readMu; a consumed frame may never be restarted.
	writeErr            error       // Owned by writeMu; a partial ciphertext may never be appended to.
	gracefulWriteClosed atomic.Bool // Published only after CloseWrite has successfully queued FIN.
}

func (c *streamConn) writeRecord(payload []byte) error {
	packet, err := c.session.Seal(payload)
	if err != nil {
		return err
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(packet)))
	if err := writeFull(c.stream, header[:]); err != nil {
		return fmt.Errorf("hyrakenx: write frame length: %w", err)
	}
	if err := writeFull(c.stream, packet); err != nil {
		return fmt.Errorf("hyrakenx: write frame body: %w", err)
	}
	return nil
}

func (c *streamConn) readRecord() ([]byte, error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	var header [2]byte
	if n, err := io.ReadFull(c.stream, header[:]); err != nil {
		if n != 0 {
			return c.failRead(err)
		}
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n < HeaderSize+16+c.session.rx.aead.Overhead() || n > maxStreamPacket {
		return c.failRead(errors.New("hyrakenx: invalid frame length"))
	}
	packet := make([]byte, n)
	if _, err := io.ReadFull(c.stream, packet); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return c.failRead(err)
	}
	body, err := c.session.Open(packet)
	if err != nil {
		return c.failRead(err)
	}
	return body, nil
}

// Once any frame bytes are consumed, an error loses that boundary. Stop only
// this receive direction; the opposite direction and other QUIC streams remain
// usable. A deadline before the length consumes zero bytes and remains retryable.
func (c *streamConn) failRead(err error) ([]byte, error) {
	c.readErr = err
	c.stream.CancelRead(1)
	return nil, err
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		body, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		c.pending = body
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	written := 0
	var batch [streamWriteBatch]byte
	var workspace packetSealWorkspace
	// QUIC Write copies accepted bytes into owned STREAM frames before returning,
	// and drops its caller slice on deadline. Scratch belongs only to writeMu.
	defer clear(batch[:])
	defer workspace.clear()
	for len(p) != 0 {
		used, consumed := 0, 0
		var ends [8]int
		var sizes [8]int
		var paddings [8]int
		records := 0
		batchLimit := len(ends)
		for records < batchLimit && consumed < len(p) {
			n := min(len(p)-consumed, MaxDatagramPayload)
			padding := 0
			if c.shaper != nil {
				decision := c.shaper.Next(time.Now(), len(p)-consumed)
				n = min(n, max(1, decision.Payload))
				padding = min(max(0, decision.Padding), MaxDatagramPayload-n)
				if records == 0 {
					batchLimit = min(len(ends), max(1, decision.Batch))
				}
			}
			packet, err := c.session.sealAppend(batch[:used+2], p[consumed:consumed+n], padding, &workspace)
			if err != nil {
				// Rekey exhaustion may follow valid records in this batch. Flush
				// those first; the next iteration reports the fail-closed limit.
				if records == 0 {
					return written, err
				}
				break
			}
			binary.BigEndian.PutUint16(batch[used:used+2], uint16(len(packet)-used-2))
			used = len(packet)
			ends[records], sizes[records] = used, n
			paddings[records] = padding
			records++
			consumed += n
		}
		sent := 0
		for sent < used {
			n, err := c.stream.Write(batch[sent:used])
			sent += n
			if err != nil || n == 0 {
				boundary := 0
				accepted, padding := 0, 0
				for i := 0; i < records && ends[i] <= sent; i++ {
					written += sizes[i]
					boundary = ends[i]
					accepted++
					padding += paddings[i]
				}
				if c.shaper != nil && c.hydraObserver != nil && accepted != 0 {
					c.hydraObserver(accepted, padding)
				}
				if err == nil {
					err = io.ErrShortWrite
				}
				err = fmt.Errorf("hyrakenx: write record batch: %w", err)
				if sent > boundary {
					// QUIC deadlines permit later writes, but this wrapper cannot
					// append a new record behind a partially accepted ciphertext.
					c.writeErr = err
					c.stream.CancelWrite(1)
				}
				return written, err
			}
		}
		if c.shaper != nil && c.hydraObserver != nil {
			padding := 0
			for i := 0; i < records; i++ {
				padding += paddings[i]
			}
			c.hydraObserver(records, padding)
		}
		written += consumed
		p = p[consumed:]
	}
	return written, nil
}

func (c *streamConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	if err := c.stream.Close(); err != nil {
		return err
	}
	c.gracefulWriteClosed.Store(true)
	return nil
}
func (c *streamConn) CloseRead() error { c.stream.CancelRead(0); return nil }
func (c *streamConn) Close() error {
	c.stream.CancelRead(0)
	// A completed CloseWrite owns reliable delivery of the queued tail and FIN.
	// CancelWrite after QUIC Close would discard that tail. Do not take writeMu:
	// Close must still interrupt blocked writes, including an in-flight
	// CloseWrite; only a prior successful CloseWrite selects graceful cleanup.
	if !c.gracefulWriteClosed.Load() {
		c.stream.CancelWrite(0)
	}
	return c.stream.Close()
}

// ForceClose aborts both directions even after a successful CloseWrite.
// Failure and policy cancellation must not depend on the application write lock.
func (c *streamConn) ForceClose() error {
	c.stream.CancelRead(0)
	c.stream.CancelWrite(0)
	return c.stream.Close()
}
func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

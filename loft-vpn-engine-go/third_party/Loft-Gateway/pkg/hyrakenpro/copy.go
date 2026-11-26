package hyrakenpro

import (
	"context"
	"errors"
	"io"
	"sync"
)

// CopyStream combines source bytes that are already ready before handing them
// to the synchronous destination writer. It never waits for a batch to fill:
// a small request is flushed even if the next source Read blocks indefinitely.
// Two 16KiB buffers plus a 32KiB scratch buffer bound working storage to 64KiB.
//
// The caller owns the relay lifetime. On cancellation or destination failure,
// CopyStream closes a closable source to interrupt its Read and joins the reader.
// A closable destination is also closed on cancellation to interrupt its Write.
// Arbitrary non-closable Readers/Writers cannot have their blocked I/O canceled;
// a non-closable source therefore uses a synchronous, non-prefetching fallback.
func CopyStream(ctx context.Context, dst io.Writer, src io.Reader) (written int64, err error) {
	if ctx == nil {
		return 0, errors.New("hyrakenpro: nil copy context")
	}
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	closer, ok := src.(io.Closer)
	if !ok {
		stop := context.AfterFunc(ctx, func() {
			if c, ok := dst.(io.Closer); ok {
				_ = c.Close()
			}
		})
		defer stop()
		return copyStreamSynchronous(ctx, dst, src)
	}
	owned, cancel := context.WithCancel(ctx)
	closeDone := make(chan struct{})
	stop := context.AfterFunc(owned, func() {
		defer close(closeDone)
		_ = closer.Close()
		if c, ok := dst.(io.Closer); ok {
			_ = c.Close()
		}
	})
	const batchSize = 16 << 10
	pending, spare := make([]byte, 0, batchSize), make([]byte, 0, batchSize)
	var mu sync.Mutex
	var readErr error
	ready, space := make(chan struct{}, 1), make(chan struct{}, 1)
	readerDone := make(chan struct{})
	notify := func(ch chan struct{}) {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	go func() {
		defer close(readerDone)
		var scratch [32 << 10]byte
		emptyReads := 0
		for {
			n, e := src.Read(scratch[:])
			if n < 0 || n > len(scratch) {
				n, e = 0, errors.New("hyrakenpro: invalid source Read count")
			}
			for off := 0; off < n; {
				mu.Lock()
				count := min(n-off, cap(pending)-len(pending))
				if count != 0 {
					pending = append(pending, scratch[off:off+count]...)
					off += count
					notify(ready)
				}
				mu.Unlock()
				if count == 0 {
					select {
					case <-space:
					case <-owned.Done():
						return
					}
				}
			}
			if e != nil {
				mu.Lock()
				readErr = e
				mu.Unlock()
				notify(ready)
				return
			}
			if n == 0 {
				emptyReads++
				if emptyReads < 100 {
					continue
				}
				mu.Lock()
				readErr = io.ErrNoProgress
				mu.Unlock()
				notify(ready)
				return
			}
			emptyReads = 0
		}
	}()
	defer func() {
		// Stop the callback before local cancellation: successful EOF must not
		// unexpectedly close caller-owned endpoints or the reverse relay half.
		if !stop() {
			<-closeDone
		}
		cancel()
		if err != nil {
			_ = closer.Close()
		}
		<-readerDone
	}()
	for {
		if e := owned.Err(); e != nil {
			return written, e
		}
		mu.Lock()
		if len(pending) == 0 {
			e := readErr
			mu.Unlock()
			if e == io.EOF {
				return written, nil
			}
			if e != nil {
				return written, e
			}
			select {
			case <-ready:
			case <-owned.Done():
			}
			continue
		}
		batch := pending
		pending, spare = spare[:0], nil
		mu.Unlock()
		notify(space)
		n, e := dst.Write(batch)
		if n < 0 || n > len(batch) {
			return written, errors.New("hyrakenpro: invalid destination Write count")
		}
		written += int64(n)
		if owned.Err() != nil {
			return written, owned.Err()
		}
		if e != nil {
			return written, e
		}
		if n != len(batch) {
			return written, io.ErrShortWrite
		}
		mu.Lock()
		spare = batch[:0]
		mu.Unlock()
	}
}

func copyStreamSynchronous(ctx context.Context, dst io.Writer, src io.Reader) (written int64, err error) {
	var buffer [32 << 10]byte
	emptyReads := 0
	for {
		if e := ctx.Err(); e != nil {
			return written, e
		}
		n, readErr := src.Read(buffer[:])
		if n < 0 || n > len(buffer) {
			return written, errors.New("hyrakenpro: invalid source Read count")
		}
		if n != 0 {
			count, e := dst.Write(buffer[:n])
			if count < 0 || count > n {
				return written, errors.New("hyrakenpro: invalid destination Write count")
			}
			written += int64(count)
			if e != nil {
				return written, e
			}
			if count != n {
				return written, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return written, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
}

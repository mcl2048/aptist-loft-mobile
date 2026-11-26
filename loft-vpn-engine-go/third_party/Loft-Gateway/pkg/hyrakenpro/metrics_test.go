package hyrakenpro

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"loft.local/hydra"
)

type recordPrefixWriter struct {
	net.Conn
	limit int
}

func (w *recordPrefixWriter) Write(packet []byte) (int, error) {
	n, err := w.Conn.Write(packet[:min(len(packet), w.limit)])
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// This uses real framed AEAD bytes over a socket pair, with no Stream caller
// available to report metrics. Late completion/cancellation belongs to the
// writer, so only fully accepted record boundaries can create observations.
func TestHydraMetricsObserveActualProducerRecordCompletion(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "complete"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			var keys recordKeys
			keys.suite = 2
			if _, err := rand.Read(keys.send[:]); err != nil {
				t.Fatal(err)
			}
			ciphers, err := newCiphers(keys)
			if err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(2 * time.Second))
			_ = right.SetDeadline(time.Now().Add(2 * time.Second))
			payload := []byte("accepted DATA")
			data := make([]byte, 5+len(payload))
			data[0] = frameData
			binary.BigEndian.PutUint32(data[1:5], 1)
			copy(data[5:], payload)
			padding := make([]byte, 5+64)
			padding[0] = framePadding
			var physical physicalConn = left
			if partial {
				physical = &recordPrefixWriter{left, 4 + len(data) + ciphers.send.Overhead()}
			}
			var records, paddingBytes atomic.Int64
			s := &session{pc: physical, keys: ciphers, hydraConfig: &hydra.Config{Enabled: true}, hydraObserver: func(r, p int) { records.Add(int64(r)); paddingBytes.Add(int64(p)) }}
			receiver := make(chan error, 1)
			go func() {
				count := 2
				if partial {
					count = 1
				}
				for i := 0; i < count; i++ {
					var header [4]byte
					if _, err := io.ReadFull(right, header[:]); err != nil {
						receiver <- err
						return
					}
					size := int(binary.BigEndian.Uint32(header[:]))
					if size < 5 || size > 1024 {
						receiver <- io.ErrUnexpectedEOF
						return
					}
					packet := make([]byte, size)
					if _, err := io.ReadFull(right, packet); err != nil {
						receiver <- err
						return
					}
					nonce := make([]byte, ciphers.send.NonceSize())
					binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(i))
					frame, err := ciphers.send.Open(nil, nonce, packet, header[:])
					if err != nil || len(frame) < 5 || i == 0 && frame[0] != frameData || i == 1 && (frame[0] != framePadding || len(frame) != 69) {
						receiver <- io.ErrUnexpectedEOF
						return
					}
				}
				receiver <- nil
			}()
			completed := new(atomic.Int64)
			request := sendRequest{records: []sendRecord{{frame: data}, {frame: padding}}, completed: completed}
			var seq uint64
			var workspace recordWorkspace
			err = s.writeRequest(&seq, &workspace, nil, request)
			if err != nil && !partial || err == nil && partial {
				t.Fatal("record writer lost complete-prefix error semantics")
			}
			if err := <-receiver; err != nil {
				t.Fatal(err)
			}
			expectedPadding := int64(64)
			if partial {
				expectedPadding = 0
			}
			if records.Load() != 1 || paddingBytes.Load() != expectedPadding || completed.Load() != int64(len(payload)) {
				t.Fatal("actual producer completion was omitted or unaccepted PAD was counted")
			}
		})
	}
}

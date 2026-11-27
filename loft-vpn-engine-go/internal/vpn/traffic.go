package vpn

import (
	"fmt"
	"io"
	"math"
	"sync/atomic"
)

type trafficUsage struct {
	upload, download int64
}

type trafficCounters struct {
	upload, download trafficCounter
}

func (c *trafficCounters) sample() trafficUsage {
	return trafficUsage{upload: c.upload.value.Load(), download: c.download.value.Load()}
}

type trafficCounter struct{ value atomic.Int64 }

func (c *trafficCounter) record(bytes int) {
	if bytes <= 0 {
		return
	}
	for {
		previous := c.value.Load()
		if previous == math.MaxInt64 || c.value.CompareAndSwap(previous, previous+min(int64(bytes), math.MaxInt64-previous)) {
			return
		}
	}
}

// The classifier can hold a prefix or deny it. Count only after the actual
// destination writer, including bytes accepted with a TCP partial-write error.
type trafficWriter struct {
	destination io.Writer
	counter     *trafficCounter
}

func (w *trafficWriter) Write(payload []byte) (int, error) {
	written, err := w.destination.Write(payload)
	if written <= len(payload) {
		w.counter.record(written)
	}
	return written, err
}

// TrafficUsage reads a passive generation-scoped meter, separate from the
// reconciliation schema. An empty record means no current or joined session.
func (r *Runtime) TrafficUsage() string {
	r.mu.Lock()
	generation, final := r.generation, r.finalTraffic
	var sample trafficUsage
	switch {
	case final != nil:
		sample = *final
	case r.state == "running" && r.startDone == nil && r.session != nil:
		sample = r.session.traffic.sample()
	default:
		r.mu.Unlock()
		return ""
	}
	r.mu.Unlock()
	flag := 0
	if final != nil {
		flag = 1
	}
	return fmt.Sprintf("1:%d:%d:%d:%d", generation, sample.upload, sample.download, flag)
}

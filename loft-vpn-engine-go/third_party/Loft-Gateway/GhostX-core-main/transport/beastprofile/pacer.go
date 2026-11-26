package beastprofile

import (
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

// Token bucket with the same 10-packet / ~1ms burst convention as the pinned
// BBR pacer. Clamp elapsed time before multiplying; long idle and clock rollback
// cannot overflow into an unlimited burst. No timer or per-packet allocation.
type beastPacer struct {
	remaining, mss congestion.ByteCount
	last           monotime.Time
	rate           func() congestion.ByteCount
}

func (p *beastPacer) burst() congestion.ByteCount {
	return max(10*p.mss, p.rate()*congestion.ByteCount(congestion.MinPacingDelay+time.Millisecond)/1e9)
}
func (p *beastPacer) budget(at monotime.Time) congestion.ByteCount {
	burst := p.burst()
	if p.last == 0 {
		return burst
	}
	remaining := min(burst, p.remaining)
	elapsed := at.Sub(p.last)
	if elapsed <= 0 {
		return remaining
	}
	rate := p.rate()
	// remaining <= burst; this division bounds the multiplication below.
	fill := time.Duration(((burst-remaining)*1e9 + rate - 1) / rate)
	if elapsed >= fill {
		return burst
	}
	return min(burst, remaining+rate*congestion.ByteCount(elapsed)/1e9)
}
func (p *beastPacer) sent(at monotime.Time, size congestion.ByteCount) {
	p.remaining = max(0, p.budget(at)-max(0, size))
	p.last = at
}
func (p *beastPacer) next() monotime.Time {
	if p.last == 0 || p.remaining >= p.mss {
		return 0
	}
	deficit := uint64(p.mss-p.remaining) * 1e9
	rate := uint64(p.rate())
	delay := time.Duration((deficit + rate - 1) / rate)
	return p.last.Add(max(congestion.MinPacingDelay, delay))
}

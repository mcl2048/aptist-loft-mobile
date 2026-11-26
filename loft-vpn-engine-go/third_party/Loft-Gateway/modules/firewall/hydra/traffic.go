package hydra

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"time"
)

const trafficVersion = 3

// TrafficOptions describes algorithm 3's wire geometry. A zero minimum selects
// inline padding. A positive minimum selects standalone padding, whose envelope
// MUST include SELECT plus all bytes of the separate record except its payload.
// Standalone payloads are 64..255 bytes. All fields are bounded by 1 MiB.
type TrafficOptions struct {
	Framing                   Framing
	StandalonePaddingMinimum  int
	StandalonePaddingEnvelope int
}

type trafficState struct {
	options      TrafficOptions
	pad          rand.ChaCha8
	runRemaining int
	small        bool
	padPosition  uint64
}

// NewTraffic selects algorithm 3. All methods, including Snapshot, require the
// caller's mutex. It performs no I/O, waits, timers, or goroutine creation.
// Data records have a ceil(capacity/4) floor when enough data is available,
// bounding record count to at most four times capacity-sized baseline records
// (plus the last partial record); this is not a wall-clock CPU guarantee.
func NewTraffic(config Config, protocol string, seed [32]byte, limits Limits, options TrafficOptions) (*Shaper, error) {
	return newTraffic(config, protocol, seed, limits, options, trafficVersion)
}

func newTraffic(config Config, protocol string, seed [32]byte, limits Limits, options TrafficOptions, algorithm uint16) (*Shaper, error) {
	f := options.Framing
	if f.Envelope < 0 || f.Envelope > maxLimit || f.PayloadPrefix < 0 || f.PayloadPrefix > maxLimit || f.MinimumPlaintext < 0 || f.MinimumPlaintext > maxLimit || options.StandalonePaddingEnvelope < 0 || options.StandalonePaddingEnvelope > maxLimit || options.StandalonePaddingMinimum < 0 || options.StandalonePaddingMinimum > 255 || (options.StandalonePaddingMinimum > 0 && options.StandalonePaddingMinimum < 64) {
		return nil, fmt.Errorf("hydra: traffic geometry out of range")
	}
	// Bounded fields make every geometry sum safe even on 32-bit platforms.
	s, err := newShaper(config, protocol, seed, limits, algorithm, f)
	if err != nil {
		return nil, err
	}
	s.traffic.options = options
	s.adjustStandaloneMaximum()
	return s, nil
}

func (s *Shaper) deriveTraffic(epoch uint64) {
	a, b := s.digest("profile", epoch, 0), s.digest("profile", epoch, 1)
	var w [16]uint32
	for i := 0; i < 8; i++ {
		w[i] = binary.BigEndian.Uint32(a[4*i : 4*i+4])
		w[i+8] = binary.BigEndian.Uint32(b[4*i : 4*i+4])
	}
	extra := s.digest("profile", epoch, 2)
	var x [8]uint32
	for i := range x {
		x[i] = binary.BigEndian.Uint32(extra[4*i : 4*i+4])
	}
	c := s.limits.MaxPayload
	floor, upper := (c+3)/4, (3*c+3)/4
	hi := upper + scale(w[0], c-upper+1)
	// Preserve broad support: the lower endpoint lies in the bottom eighth
	// above the quarter-capacity hard floor, rather than near the upper bound.
	lo := floor + scale(w[1], min((c+7)/8, hi-floor)+1)
	runMin := 2 + scale(w[7], 5)
	stride := 1 + scale(w[12], 8)
	batchMin := 1 + scale(w[3], 4)
	s.profile = Snapshot{Generation: epoch, AlgorithmVersion: trafficVersion,
		ChunkMin: lo, ChunkMax: hi, ChunkDistribution: scale(w[2], 6),
		Batch: batchMin, BatchMin: batchMin, BatchMax: batchMin + 1 + scale(w[4], 8-batchMin),
		PaddingMax: scale(w[5], s.limits.MaxPadding+1), PaddingChance: 20 + scale(w[6], 61), PaddingDistribution: scale(w[8], 6),
		BucketCount: 3 + scale(w[9], 6), BucketJitter: scale(w[10], 36), MixtureWeight: 20 + scale(w[11], 61), BandWidth: 5 + scale(w[13], 21),
		PaddingRatioPermille: 50 + scale(w[14], 201), RunMin: runMin, RunMax: runMin + scale(w[15], 17-runMin), SmallChance: 20 + scale(x[0], 61),
		SmallBand: 15 + scale(x[1], 21), LargeBand: 65 + scale(x[2], 21), PaddingStride: stride, PaddingPhase: scale(x[3], stride),
		AlignmentGrid: 16 << scale(x[4], 5), AlignmentChance: 25 + scale(x[6], 51)}
	s.profile.AlignmentResidue = scale(x[5], s.profile.AlignmentGrid)
	s.adjustStandaloneMaximum()
	s.fixed = s.digest("fixed-record", epoch, 0)
	p := s.profile
	s.fixedPayload = sampleEnhanced(binary.BigEndian.Uint32(s.fixed[:4]), binary.BigEndian.Uint32(s.fixed[4:8]), lo, hi, p.ChunkDistribution, p)
	s.jitter.Seed(s.digest("jitter-record", epoch, 0))
	s.traffic.pad.Seed(s.digest("jitter-padding", epoch, 0))
	s.traffic.runRemaining = 0
	s.traffic.padPosition = 0
}

func (s *Shaper) nextTraffic(available int) Decision {
	if s.algorithm == DynamicV2Version && s.config.AutoJitter {
		return s.nextDynamicV2(available)
	}
	p := s.profile
	d := Decision{Batch: p.Batch}
	if available <= 0 {
		return d
	}
	payload := s.fixedPayload
	if s.config.AutoJitter {
		if s.algorithm == AdaptiveVersion || s.algorithm == DynamicVersion {
			payload, d.Batch = s.adaptivePayload()
		} else {
			if s.traffic.runRemaining == 0 {
				r := s.jitter.Uint64()
				s.traffic.small = percent(uint32(r)) < p.SmallChance
				s.traffic.runRemaining = p.RunMin + scale(uint32(r>>32), p.RunMax-p.RunMin+1)
			}
			s.traffic.runRemaining--
			lo, hi := p.ChunkMin, p.ChunkMax
			if s.traffic.small {
				hi = lo + (hi-lo)*p.SmallBand/100
				d.Batch = p.BatchMin
			} else {
				lo = lo + (hi-lo)*p.LargeBand/100
				d.Batch = p.BatchMax
			}
			r := s.jitter.Uint64()
			payload = sampleEnhanced(uint32(r), uint32(r>>32), lo, hi, p.ChunkDistribution, p)
		}
	}
	d.Payload = min(available, payload)
	if s.traffic.options.StandalonePaddingMinimum > 0 {
		return d
	}
	candidate, align := s.trafficPadding()
	if s.limits.PaddingPerSecond == 0 {
		return d
	}
	allowance := min(p.PaddingMax, d.Payload*p.PaddingRatioPermille/1000, d.Payload/4, s.limits.MaxPayload-d.Payload, int(s.tokens/1e9))
	padding := min(candidate, allowance)
	if align {
		grid, residue := p.AlignmentGrid, p.AlignmentResidue
		if s.algorithm == DynamicVersion && s.config.AutoJitter {
			grid, residue = 1<<s.adaptive.noise.gridShift, int(s.adaptive.noise.residue)
		}
		if aligned, ok := s.framing.alignmentPadding(d.Payload, allowance, grid, residue); ok {
			padding = aligned
		}
	}
	if s.framing.length(d.Payload, padding) > s.framing.length(d.Payload, 0) {
		d.Padding = padding
		s.tokens -= int64(padding) * 1e9
	}
	return d
}

// trafficPadding has independent randomness and cadence: queue-ahead record
// decisions cannot perturb subsequent standalone padding. With jitter disabled,
// cadence is a fixed epoch stride and the candidate is constant within the epoch.
func (s *Shaper) trafficPadding() (int, bool) {
	p := s.profile
	if s.algorithm == DynamicVersion && s.config.AutoJitter {
		s.advanceNoiseRun()
	}
	pos := s.traffic.padPosition
	s.traffic.padPosition++
	if (s.algorithm == AdaptiveVersion || s.algorithm == DynamicVersion) && s.config.AutoJitter {
		if s.adaptive.padRemaining > 0 {
			s.adaptive.padRemaining--
			return 0, false
		}
		r := s.traffic.pad.Uint64()
		s.adaptive.padRemaining = sampleEnhanced(uint32(r), uint32(r>>32), p.PaddingGapMin, p.PaddingGapMax, p.PaddingGapDistribution, p) - 1
	} else {
		if pos%uint64(p.PaddingStride) != uint64(p.PaddingPhase) {
			return 0, false
		}
	}
	a, b := binary.BigEndian.Uint32(s.fixed[8:12]), binary.BigEndian.Uint32(s.fixed[12:16])
	gate := binary.BigEndian.Uint32(s.fixed[16:20])
	chance := a
	if s.algorithm == AdaptiveVersion || s.algorithm == DynamicVersion || s.algorithm == DynamicV2Version {
		chance = binary.BigEndian.Uint32(s.fixed[20:24])
	}
	if s.config.AutoJitter {
		r := s.traffic.pad.Uint64()
		a, b = uint32(r), uint32(r>>32)
		extra := s.traffic.pad.Uint64()
		gate = uint32(extra)
		if s.algorithm == AdaptiveVersion || s.algorithm == DynamicVersion {
			chance = uint32(extra >> 32)
		} else {
			chance = a
		}
	}
	align := percent(gate) < p.AlignmentChance
	minimum, maximum := s.traffic.options.StandalonePaddingMinimum, p.PaddingMax
	if maximum < minimum {
		return 0, false
	}
	if percent(chance) >= p.PaddingChance {
		return 0, align
	}
	family := p.PaddingDistribution
	if s.algorithm == DynamicVersion && s.config.AutoJitter {
		family = int(s.adaptive.noise.family)
		maximum = minimum + (maximum-minimum)*int(s.adaptive.noise.intensity)/100
	}
	return sampleEnhanced(a, b, minimum, maximum, family, p), align
}

// Reflect the actual standalone cap in Snapshot, including disabled-padding
// configurations whose MaxPadding is below the required minimum.
func (s *Shaper) adjustStandaloneMaximum() {
	if minimum := s.traffic.options.StandalonePaddingMinimum; minimum > 0 {
		if s.algorithm == DynamicV2Version {
			// Domain6 keeps the operator-permitted support intact. Epoch randomness
			// selects candidates/runs, not a cap that can collapse the range to64B.
			s.profile.PaddingMax = min(255, s.limits.MaxPadding)
			return
		}
		s.profile.PaddingMax = min(255, s.limits.MaxPadding, max(minimum, s.profile.PaddingMax))
	}
}

// NextStandalonePadding returns a separately transmitted padding payload, charging
// its entire envelope and payload. Call exactly at dispatch, under the same mutex
// as Next. A failed send retains its charge. An infeasible minimum is skipped;
// no attempt rounds the budget up. Inline, disabled, and invalid calls do nothing.
func (s *Shaper) NextStandalonePadding(now time.Time, payload int) int {
	if (s.algorithm != trafficVersion && s.algorithm != AdaptiveVersion && s.algorithm != DynamicVersion && s.algorithm != DynamicV2Version) || !s.config.Enabled || s.traffic.options.StandalonePaddingMinimum == 0 || payload <= 0 || payload > s.limits.MaxPayload {
		return 0
	}
	s.advance(now)
	if s.algorithm == DynamicV2Version && s.config.AutoJitter {
		return s.nextDynamicV2Standalone(payload)
	}
	candidate, _ := s.trafficPadding()
	if candidate == 0 || s.limits.PaddingPerSecond == 0 {
		return 0
	}
	envelope := s.traffic.options.StandalonePaddingEnvelope
	allowance := min(payload/4, int(s.tokens/1e9)) - envelope
	if allowance < s.traffic.options.StandalonePaddingMinimum {
		return 0
	}
	padding := min(candidate, allowance)
	s.tokens -= int64(envelope+padding) * 1e9
	return padding
}

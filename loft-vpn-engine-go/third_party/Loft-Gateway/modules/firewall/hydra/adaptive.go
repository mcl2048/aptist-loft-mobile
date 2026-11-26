package hydra

import (
	"encoding/binary"
	"math"
	"time"
)

// AdaptiveVersion is a local scheduling derivation domain, never a wire version.
const AdaptiveVersion = 4

type adaptiveState struct {
	low, high, batch int // Current run's bounded interval and ready-record ceiling.
	padRemaining     int // Accepted padding opportunities until the next renewal event.
	nextBoundary     time.Duration
	nextReachable    bool     // False when the mathematical boundary exceeds Duration.
	noise            noiseRun // Reuses alignment padding after nextReachable on amd64.
}

// NewAdaptive selects three-regime adaptive shaping with independent renewal
// padding. Options describe existing wire geometry, not new protocol fields.
// All methods require the caller's writer mutex; no I/O or waits are performed.
func NewAdaptive(config Config, protocol string, seed [32]byte, limits Limits, options TrafficOptions) (*Shaper, error) {
	return newTraffic(config, protocol, seed, limits, options, AdaptiveVersion)
}

func (s *Shaper) deriveAdaptive(epoch uint64) {
	// Existing bounded geometry, families and independent generators are reused
	// under domain4. Legacy constructors continue through their unchanged paths.
	s.deriveTraffic(epoch)
	r := s.digest("adaptive-profile", epoch, 0)
	var w [8]uint32
	for i := range w {
		w[i] = binary.BigEndian.Uint32(r[4*i : 4*i+4])
	}
	p := &s.profile
	p.AlgorithmVersion = AdaptiveVersion
	c := s.limits.MaxPayload
	percentFloor := s.config.ChunkMinPercent
	if percentFloor == 0 {
		percentFloor = 25
	}
	floor := (c*percentFloor + 99) / 100
	p.ChunkMin = floor + scale(w[0], min((c+7)/8, p.ChunkMax-floor)+1)
	p.SmallChance = 15 + scale(w[1], 46)
	p.MiddleChance = 15 + scale(w[2], min(60, 90-p.SmallChance)-14)
	p.SmallBand = 20 + scale(w[3], 36)
	p.LargeBand = 45 + scale(w[4], 36)
	p.MiddleBand = 20 + scale(w[5], 46)
	p.RegimeJitter = 5 + scale(w[6], 16)
	p.RunDistribution = scale(w[7], 6)
	extra := s.digest("adaptive-profile", epoch, 1)
	for i := range w {
		w[i] = binary.BigEndian.Uint32(extra[4*i : 4*i+4])
	}
	minimum, maximum := s.config.BurstMinRecords, s.config.BurstMaxRecords
	if minimum == 0 {
		minimum = 2
	}
	if maximum == 0 {
		maximum = 32
	}
	// Keep useful random length support whenever the operator permits multiple
	// values. Only an effective point range intentionally derives a fixed run.
	minimumCeiling := minimum + min(4, max(0, maximum-minimum-1))
	p.RunMin = minimum + scale(w[0], minimumCeiling-minimum+1)
	maximumFloor := p.RunMin
	if maximum > p.RunMin {
		maximumFloor++
	}
	p.RunMax = maximumFloor + scale(w[1], maximum-maximumFloor+1)
	p.BatchJitter = 1 + scale(w[2], 3)
	gap := s.config.PaddingGapMaxRecords
	if gap == 0 {
		gap = 16
	}
	p.PaddingGapMin, p.PaddingGapMax = 1, 1
	if gap > 1 {
		p.PaddingGapMax = 2 + scale(w[3], gap-1)
		p.PaddingGapMin = 1 + scale(w[4], min(4, p.PaddingGapMax-1))
	}
	p.PaddingGapDistribution = scale(w[5], 6)
	// Fixed mode intentionally retains an epoch stride and one PAD candidate.
	p.PaddingStride = 1 + scale(w[6], gap)
	p.PaddingPhase = scale(w[7], p.PaddingStride)
	s.fixedPayload = sampleEnhanced(binary.BigEndian.Uint32(s.fixed[:4]), binary.BigEndian.Uint32(s.fixed[4:8]), p.ChunkMin, p.ChunkMax, p.ChunkDistribution, *p)
	s.adaptive.padRemaining = 0
	if s.config.RotationJitterPercent > 0 {
		s.adaptive.nextBoundary, s.adaptive.nextReachable = s.rotationBoundary(epoch + 1)
	}
}

func (s *Shaper) adaptivePayload() (int, int) {
	p := s.profile
	if s.traffic.runRemaining == 0 {
		r := s.jitter.Uint64()
		selector := percent(uint32(r))
		lo, hi := p.ChunkMin, p.ChunkMax
		span := hi - lo
		batch := (p.BatchMin + p.BatchMax) / 2
		switch {
		case selector < p.SmallChance:
			hi = lo + span*p.SmallBand/100
			batch = p.BatchMin
		case selector < p.SmallChance+p.MiddleChance:
			width := span * p.MiddleBand / 100
			lo += (span - width) / 2
			hi = lo + width
		default:
			lo += span * p.LargeBand / 100
			batch = p.BatchMax
		}
		// Shift the whole interval, then move it back inside the profile. Preserve
		// its original width; clipping endpoints separately would create point bands.
		radius := span * p.RegimeJitter / 100
		shift := scale(uint32(r>>32), 2*radius+1) - radius
		width := hi - lo
		lo = min(p.ChunkMax-width, max(p.ChunkMin, lo+shift))
		hi = lo + width
		r = s.jitter.Uint64()
		s.traffic.runRemaining = sampleEnhanced(uint32(r), uint32(r>>32), p.RunMin, p.RunMax, p.RunDistribution, p)
		r = s.jitter.Uint64()
		batch = min(8, max(1, batch+scale(uint32(r), 2*p.BatchJitter+1)-p.BatchJitter))
		s.adaptive.low, s.adaptive.high, s.adaptive.batch = lo, hi, batch
	}
	s.traffic.runRemaining--
	r := s.jitter.Uint64()
	return sampleEnhanced(uint32(r), uint32(r>>32), s.adaptive.low, s.adaptive.high, p.ChunkDistribution, p), s.adaptive.batch
}

// rotationBoundary computes B(n)=n*base+nonnegative epoch-local offset. A false
// result means the exact boundary cannot be represented; it must not be treated
// as reached merely because elapsed itself saturates at MaxInt64.
func (s *Shaper) rotationBoundary(epoch uint64) (time.Duration, bool) {
	if epoch == 0 {
		return 0, true
	}
	base := int64(s.config.RotationSeconds) * int64(time.Second)
	if epoch > uint64(math.MaxInt64/base) {
		return time.Duration(math.MaxInt64), false
	}
	value := int64(epoch) * base
	seconds := s.config.RotationSeconds
	maximum := min(seconds*s.config.RotationJitterPercent/100, seconds-10, 86400-seconds)
	if maximum == 0 {
		return time.Duration(value), true
	}
	r := s.digest("rotation-boundary", epoch, 0)
	offset := int64(scale(binary.BigEndian.Uint32(r[:4]), maximum+1)) * int64(time.Second)
	if offset > math.MaxInt64-value {
		return time.Duration(math.MaxInt64), false
	}
	return time.Duration(value + offset), true
}

func (s *Shaper) adaptiveEpoch(elapsed time.Duration) uint64 {
	// Most records perform one comparison. No random generation occurs until a
	// cached boundary is crossed, including repeated calls at saturated elapsed.
	if !s.adaptive.nextReachable || elapsed < s.adaptive.nextBoundary {
		return s.profile.Generation
	}
	base := time.Duration(s.config.RotationSeconds) * time.Second
	nominal := uint64(elapsed / base)
	boundary, reachable := s.rotationBoundary(nominal)
	if !reachable || elapsed < boundary {
		nominal--
	}
	return nominal
}

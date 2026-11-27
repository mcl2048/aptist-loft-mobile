// Package hydra provides bounded, deployment-specific record shaping.
// It performs no I/O, creates no goroutines, and imposes no timing delays.
package hydra

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"time"
)

// Version separates derivation domains when shaping algorithms change.
const Version = 1
const maxLimit = 1 << 20

// Config retains the original operator fields and optional adaptive parameters.
// Zero disables shaping and omits all advanced JSON fields. AutoJitter must be
// explicitly enabled; false keeps requested DATA decisions fixed within epochs.
type Config struct {
	Enabled         bool `json:"enabled"`
	AutoJitter      bool `json:"auto_jitter"`
	RotationSeconds int  `json:"rotation_seconds"`
	// Advanced zero values select local defaults without rewriting operator JSON.
	RotationJitterPercent int `json:"rotation_jitter_percent,omitempty"`
	ChunkMinPercent       int `json:"chunk_min_percent,omitempty"`
	BurstMinRecords       int `json:"burst_min_records,omitempty"`
	BurstMaxRecords       int `json:"burst_max_records,omitempty"`
	PaddingGapMaxRecords  int `json:"padding_gap_max_records,omitempty"`
}

// Advanced reports whether the policy requires the adaptive sender capability.
func (c Config) Advanced() bool {
	return c.RotationJitterPercent != 0 || c.ChunkMinPercent != 0 || c.BurstMinRecords != 0 || c.BurstMaxRecords != 0 || c.PaddingGapMaxRecords != 0
}

// Normalize validates even disabled configurations. Zero rotation selects 300s.
func Normalize(c Config) (Config, error) {
	if c.RotationSeconds == 0 {
		c.RotationSeconds = 300
	}
	if c.RotationSeconds < 10 || c.RotationSeconds > 86400 {
		return Config{}, fmt.Errorf("hydra: rotation_seconds must be 10..86400 or zero")
	}
	if c.RotationJitterPercent < 0 || c.RotationJitterPercent > 40 ||
		(c.ChunkMinPercent != 0 && (c.ChunkMinPercent < 25 || c.ChunkMinPercent > 50)) ||
		c.BurstMinRecords < 0 || c.BurstMinRecords > 32 || c.BurstMaxRecords < 0 || c.BurstMaxRecords > 32 ||
		c.PaddingGapMaxRecords < 0 || c.PaddingGapMaxRecords > 64 {
		return Config{}, fmt.Errorf("hydra: advanced parameters out of range")
	}
	minimum, maximum := c.BurstMinRecords, c.BurstMaxRecords
	if minimum == 0 {
		minimum = 2
	}
	if maximum == 0 {
		maximum = 32
	}
	if minimum > maximum {
		return Config{}, fmt.Errorf("hydra: burst_min_records exceeds effective burst_max_records")
	}
	return c, nil
}

// Limits describes adapter capacity, independent of protocol framing.
// MaxPayload is the TOTAL capacity shared by user payload and Hydra padding;
// adapters must subtract framing and mandatory encryption padding beforehand.
// Each field is bounded by 1 MiB (rates are bytes/second). MaxPayload must be
// positive. Padding fields may be zero, disabling optional padding.
type Limits struct {
	MaxPayload       int
	MaxPadding       int
	PaddingBurst     int
	PaddingPerSecond int
}

// Decision describes one logical record, not a physical network datagram.
// Batch is a submission ceiling for records already available, never a wait.
type Decision struct{ Payload, Padding, Batch int }

// Snapshot contains safe shaping parameters, never seed or random-generator state.
// Generation counts rotations from the first enabled Next or valid standalone
// padding call. Adaptive rotation jitter changes boundaries, not token credit.
// PaddingChance gates the ordinary random-padding candidate. In algorithm 2,
// AlignmentChance independently gates a target attempt, which can fail because
// of capacity or budget; neither field denotes achieved total padding incidence.
// AlgorithmVersion is 0 for the legacy New API (domain Version=1), or 2 for
// NewEnhanced, 3 for NewTraffic, 4 for NewAdaptive, 5 for NewDynamic, or 6 for
// NewDynamicV2. Additional zero fields
// preserve legacy values, not struct layout.
type Snapshot struct {
	Generation                                            uint64
	ChunkMin, ChunkMax, ChunkDistribution                 int
	Batch, PaddingMax, PaddingChance, PaddingDistribution int
	// Enhanced parameters are zero for the legacy algorithm.
	AlgorithmVersion, BucketCount, BucketJitter      int
	MixtureWeight, BandWidth, PaddingRatioPermille   int
	AlignmentGrid, AlignmentResidue, AlignmentChance int
	// Algorithm 3: run lengths 2..16, small probability 20..80 percent,
	// regime bands in percent, batch ceilings 1..8, cadence stride 1..8,
	// phase 0..stride-1. These are profile parameters, not live run state.
	RunMin, RunMax, SmallChance, SmallBand, LargeBand int
	BatchMin, BatchMax, PaddingStride, PaddingPhase   int
	// Adaptive parameters are zero for algorithms 1..3; no live state is exposed.
	MiddleChance, MiddleBand, RegimeJitter               int
	RunDistribution, BatchJitter                         int
	PaddingGapMin, PaddingGapMax, PaddingGapDistribution int
}

// Shaper is owned by one caller writer mutex. Serialize ALL calls, including
// Snapshot, under that mutex; it intentionally has no internal synchronization.
// Do not copy a Shaper after first use. One instance budgets one writer lifetime.
type Shaper struct {
	config       Config
	limits       Limits
	seed         [32]byte
	protocol     string
	profile      Snapshot
	origin, last time.Time
	started      bool
	tokens       int64 // fractional byte units: one byte = 1e9 units
	fixed        [32]byte
	fixedPayload int
	fixedPadding int
	fixedAlign   bool // Enhanced fixed candidate; budgets are still applied per record.
	jitter       rand.ChaCha8
	algorithm    uint16 // Zero retains Version for legacy callers.
	framing      Framing
	traffic      trafficState
	adaptive     adaptiveState
}

// New validates configuration, protocol domain, and all limits before use.
// Use a deployment-specific secret seed; use separate instances for writers.
func New(config Config, protocol string, seed [32]byte, limits Limits) (*Shaper, error) {
	return newShaper(config, protocol, seed, limits, 0, Framing{})
}

func newShaper(config Config, protocol string, seed [32]byte, limits Limits, algorithm uint16, framing Framing) (*Shaper, error) {
	c, err := Normalize(config)
	if err != nil {
		return nil, err
	}
	if algorithm != AdaptiveVersion && algorithm != DynamicVersion && algorithm != DynamicV2Version && c.Advanced() {
		return nil, fmt.Errorf("hydra: advanced parameters require adaptive sender")
	}
	if len(protocol) == 0 || len(protocol) > 256 {
		return nil, fmt.Errorf("hydra: protocol must contain 1..256 bytes")
	}
	if limits.MaxPayload < 1 || limits.MaxPayload > maxLimit ||
		limits.MaxPadding < 0 || limits.MaxPadding > limits.MaxPayload ||
		limits.PaddingBurst < 0 || limits.PaddingBurst > maxLimit ||
		limits.PaddingPerSecond < 0 || limits.PaddingPerSecond > maxLimit {
		return nil, fmt.Errorf("hydra: limits out of range (maximum 1 MiB)")
	}
	s := &Shaper{config: c, limits: limits, seed: seed, protocol: protocol, tokens: int64(limits.PaddingBurst) * 1e9, algorithm: algorithm, framing: framing}
	s.derive(0)
	return s, nil
}

// Snapshot returns the current profile without advancing the clock.
func (s *Shaper) Snapshot() Snapshot { return s.profile }

func (s *Shaper) digest(domain string, epoch, counter uint64) [32]byte {
	algorithm := s.algorithm
	if algorithm == 0 {
		algorithm = Version
	}
	const prefix = "loft/hydra/"
	const maxDomainBytes = 64 // All internal domains are short literals.
	const maxProtocolBytes = 256
	const headerBytes = 20
	if len(domain) > maxDomainBytes || len(s.protocol) > maxProtocolBytes {
		// Preserve the original HMAC for private inputs beyond the stack bound.
		mac := hmac.New(sha256.New, s.seed[:])
		var header [headerBytes]byte
		binary.BigEndian.PutUint16(header[:2], algorithm)
		binary.BigEndian.PutUint16(header[2:4], uint16(len(s.protocol)))
		binary.BigEndian.PutUint64(header[4:12], epoch)
		binary.BigEndian.PutUint64(header[12:20], counter)
		// hash.Hash.Write always returns len(p), nil; these errors cannot occur.
		_, _ = mac.Write([]byte(prefix + domain + "\x00"))
		_, _ = mac.Write(header[:])
		_, _ = mac.Write([]byte(s.protocol))
		var result [32]byte
		copy(result[:], mac.Sum(nil))
		return result
	}
	// RFC2104 HMAC with the fixed 32-byte seed, zero-padded to SHA256's block
	// size. Local workspaces avoid per-digest hash objects and preserve Shaper's
	// size. Seed bytes affect only XOR operands, never branches or loop bounds.
	var inner [sha256.BlockSize + len(prefix) + maxDomainBytes + 1 + headerBytes + maxProtocolBytes]byte
	var outer [sha256.BlockSize + sha256.Size]byte
	for i := 0; i < sha256.BlockSize; i++ {
		inner[i], outer[i] = 0x36, 0x5c
	}
	for i, value := range s.seed {
		inner[i] ^= value
		outer[i] ^= value
	}
	n := sha256.BlockSize
	n += copy(inner[n:], prefix)
	n += copy(inner[n:], domain)
	inner[n] = 0
	n++
	header := inner[n : n+headerBytes]
	binary.BigEndian.PutUint16(header[:2], algorithm)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(s.protocol)))
	binary.BigEndian.PutUint64(header[4:12], epoch)
	binary.BigEndian.PutUint64(header[12:20], counter)
	n += headerBytes
	n += copy(inner[n:], s.protocol)
	result := sha256.Sum256(inner[:n])
	copy(outer[sha256.BlockSize:], result[:])
	return sha256.Sum256(outer[:])
}

func (s *Shaper) derive(epoch uint64) {
	if s.algorithm == DynamicV2Version {
		s.deriveDynamicV2(epoch)
		return
	}
	if s.algorithm == DynamicVersion {
		s.deriveDynamic(epoch)
		return
	}
	if s.algorithm == AdaptiveVersion {
		s.deriveAdaptive(epoch)
		return
	}
	if s.algorithm == trafficVersion {
		s.deriveTraffic(epoch)
		return
	}
	if s.algorithm == enhancedVersion {
		s.deriveEnhanced(epoch)
		return
	}
	r := s.digest("profile", epoch, 0)
	word := func(i int) int { return int(binary.BigEndian.Uint32(r[4*i:4*i+4]) & 0x7fffffff) }
	// Keep large queued writes efficient: no profile may fragment them below
	// half the adapter capacity. Tiny available writes still pass immediately.
	capacity := s.limits.MaxPayload
	hiFloor := (3*capacity + 3) / 4
	loFloor := (capacity + 1) / 2
	hi := hiFloor + word(0)%(capacity-hiFloor+1)
	lo := loFloor + word(1)%(hi-loFloor+1)
	s.profile = Snapshot{Generation: epoch, ChunkMin: lo, ChunkMax: hi,
		ChunkDistribution: word(2) % 3, Batch: 1 + word(3)%8,
		PaddingMax: word(4) % (s.limits.MaxPadding + 1), PaddingChance: 10 + word(5)%81,
		PaddingDistribution: word(6) % 3}
	s.fixed = s.digest("fixed-record", epoch, 0)
	p := s.profile
	s.fixedPayload = sample(binary.BigEndian.Uint32(s.fixed[:4]), p.ChunkMin, p.ChunkMax, p.ChunkDistribution)
	s.fixedPadding = 0
	if percent(binary.BigEndian.Uint32(s.fixed[4:8])) < p.PaddingChance {
		s.fixedPadding = sample(binary.BigEndian.Uint32(s.fixed[8:12]), 0, p.PaddingMax, p.PaddingDistribution)
	}
	s.jitter.Seed(s.digest("jitter-record", epoch, 0))
}

// percent maps all 2^32 inputs onto 100 buckets with at most one input
// difference between bucket populations, without rejection or modulo bias.
func percent(r uint32) int { return int(uint64(r) * 100 >> 32) }

func sample(r uint32, lo, hi, distribution int) int {
	span := hi - lo
	switch distribution {
	case 1: // Four evenly spaced buckets, inclusive of both endpoints.
		return lo + span*int(r%4)/3
	case 2: // Bimodal lower/upper quartiles.
		quarter := span / 4
		n := int((r >> 1) % uint32(quarter+1))
		if r&1 == 0 {
			return lo + n
		}
		return hi - n
	default:
		return lo + int(r%uint32(span+1))
	}
}

func (s *Shaper) advance(now time.Time) {
	if !s.started {
		s.started = true
		s.origin = now
		s.last = now
		return
	}
	// Preserve a high-water clock: rollback must neither refill nor rotate back.
	if now.Before(s.last) {
		return
	}
	elapsed := now.Sub(s.last)
	if s.limits.PaddingPerSecond > 0 {
		capUnits := int64(s.limits.PaddingBurst) * 1e9
		rate := int64(s.limits.PaddingPerSecond)
		// Saturate BEFORE multiplying elapsed nanoseconds by rate.
		missing := capUnits - s.tokens
		fillTime := (missing + rate - 1) / rate
		if int64(elapsed) >= fillTime {
			s.tokens = capUnits
		} else {
			s.tokens += int64(elapsed) * rate
		}
	}
	s.last = now
	elapsedOrigin := now.Sub(s.origin)
	epoch := uint64(elapsedOrigin / (time.Duration(s.config.RotationSeconds) * time.Second))
	if (s.algorithm == AdaptiveVersion || s.algorithm == DynamicVersion || s.algorithm == DynamicV2Version) && s.config.RotationJitterPercent > 0 {
		epoch = s.adaptiveEpoch(elapsedOrigin)
	}
	if epoch > s.profile.Generation {
		s.derive(epoch)
	}
}

// Next consumes the optional padding budget for one immediately submitted record.
// Call only when sending, under the writer mutex. A failed write conservatively
// retains the charge. now should come from time.Now (with monotonic clock).
// Nonpositive available yields no payload or padding. Padding is always <=25%
// of this record's payload and Payload+Padding never exceeds MaxPayload.
// Mandatory encryption padding is exclusively the adapter's responsibility.
func (s *Shaper) Next(now time.Time, available int) Decision {
	if !s.config.Enabled {
		return Decision{Payload: min(max(available, 0), s.limits.MaxPayload), Batch: 8}
	}
	s.advance(now)
	if s.algorithm == trafficVersion || s.algorithm == AdaptiveVersion || s.algorithm == DynamicVersion || s.algorithm == DynamicV2Version {
		return s.nextTraffic(available)
	}
	if s.algorithm == enhancedVersion {
		return s.nextEnhanced(available)
	}
	p := s.profile
	d := Decision{Batch: p.Batch}
	if available <= 0 {
		return d
	}
	payload, padding := s.fixedPayload, s.fixedPadding
	if s.config.AutoJitter {
		var r [16]byte
		binary.BigEndian.PutUint64(r[:8], s.jitter.Uint64())
		binary.BigEndian.PutUint64(r[8:], s.jitter.Uint64())
		payload = sample(binary.BigEndian.Uint32(r[:4]), p.ChunkMin, p.ChunkMax, p.ChunkDistribution)
		padding = 0
		if percent(binary.BigEndian.Uint32(r[4:8])) < p.PaddingChance {
			padding = sample(binary.BigEndian.Uint32(r[8:12]), 0, p.PaddingMax, p.PaddingDistribution)
		}
	}
	d.Payload = min(available, payload)
	if s.limits.PaddingPerSecond > 0 {
		d.Padding = min(padding, d.Payload/4, s.limits.MaxPayload-d.Payload, int(s.tokens/1e9))
		s.tokens -= int64(d.Padding) * 1e9
	}
	return d
}

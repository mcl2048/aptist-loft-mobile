package hydra

import (
	"encoding/binary"
	"fmt"
)

const enhancedVersion = 2

// Framing describes adapter bytes, without changing the adapter's wire format.
// A submitted record occupies Envelope + max(MinimumPlaintext,
// PayloadPrefix + payload + padding) bytes. Each field is bounded by 1 MiB.
// Zero values describe an unframed payload. Framing never expands Limits.
type Framing struct {
	Envelope, PayloadPrefix, MinimumPlaintext int
}

// NewEnhanced selects automatic shaping algorithm 2 with the same operator
// configuration as New. The algorithm domain is local: it changes neither the
// protocol version nor any encryption key, nonce, or receiver requirement.
// Like New, all operations require the caller's writer mutex.
func NewEnhanced(config Config, protocol string, seed [32]byte, limits Limits, framing Framing) (*Shaper, error) {
	if framing.Envelope < 0 || framing.Envelope > maxLimit ||
		framing.PayloadPrefix < 0 || framing.PayloadPrefix > maxLimit ||
		framing.MinimumPlaintext < 0 || framing.MinimumPlaintext > maxLimit {
		return nil, fmt.Errorf("hydra: framing out of range (maximum 1 MiB per field)")
	}
	return newShaper(config, protocol, seed, limits, enhancedVersion, framing)
}

// scale maps a 32-bit word into n buckets, differing by at most one preimage.
// All callers provide positive, bounded n; no rejection loop is necessary.
func scale(r uint32, n int) int { return int(uint64(r) * uint64(n) >> 32) }

func (s *Shaper) deriveEnhanced(epoch uint64) {
	a, b := s.digest("profile", epoch, 0), s.digest("profile", epoch, 1)
	var words [16]uint32
	for i := 0; i < 8; i++ {
		words[i] = binary.BigEndian.Uint32(a[4*i : 4*i+4])
		words[i+8] = binary.BigEndian.Uint32(b[4*i : 4*i+4])
	}
	c := s.limits.MaxPayload
	hiFloor, loFloor := (3*c+3)/4, (c+1)/2
	hi := hiFloor + scale(words[0], c-hiFloor+1)
	// Preserve usable distribution width, rather than deriving a near-point
	// interval that hides the selected family. Tiny capacities degrade safely.
	width := min(hi-loFloor, (c+7)/8)
	lo := loFloor + scale(words[1], hi-width-loFloor+1)
	grid := 32 << scale(words[12], 3)
	s.profile = Snapshot{
		Generation: epoch, AlgorithmVersion: enhancedVersion,
		ChunkMin: lo, ChunkMax: hi, ChunkDistribution: scale(words[2], 6),
		Batch: 1 + scale(words[3], 8), PaddingMax: scale(words[4], s.limits.MaxPadding+1),
		PaddingChance: 10 + scale(words[5], 81), PaddingDistribution: scale(words[6], 6),
		BucketCount: 3 + scale(words[7], 6), BucketJitter: scale(words[8], 36),
		MixtureWeight: 20 + scale(words[9], 61), BandWidth: 5 + scale(words[10], 21),
		PaddingRatioPermille: 25 + scale(words[11], 226),
		AlignmentGrid:        grid, AlignmentResidue: scale(words[13], grid),
		AlignmentChance: 25 + scale(words[14], 51),
	}
	s.fixed = s.digest("fixed-record", epoch, 0)
	var fixed [6]uint32
	for i := range fixed {
		fixed[i] = binary.BigEndian.Uint32(s.fixed[4*i : 4*i+4])
	}
	p := s.profile
	s.fixedPayload = sampleEnhanced(fixed[0], fixed[1], p.ChunkMin, p.ChunkMax, p.ChunkDistribution, p)
	s.fixedPadding = 0
	if percent(fixed[2]) < p.PaddingChance {
		s.fixedPadding = sampleEnhanced(fixed[3], fixed[4], 0, p.PaddingMax, p.PaddingDistribution, p)
	}
	s.fixedAlign = percent(fixed[5]) < p.AlignmentChance
	s.jitter.Seed(s.digest("jitter-record", epoch, 0))
}

// sampleEnhanced uses independent words for shape selection and displacement.
// Families: uniform, jittered lattice, weighted endpoints, center, lower, upper.
// Jitter is a percentage of lattice spacing; endpoints are clamped to bounds.
func sampleEnhanced(a, b uint32, lo, hi, family int, p Snapshot) int {
	span := hi - lo
	x, y := scale(a, span+1), scale(b, span+1)
	switch family {
	case 1:
		spacing := span / (p.BucketCount - 1)
		center := span * scale(a, p.BucketCount) / (p.BucketCount - 1)
		radius := spacing * p.BucketJitter / 100
		return lo + min(span, max(0, center+scale(b, 2*radius+1)-radius))
	case 2:
		band := span * p.BandWidth / 100
		offset := scale(b, band+1)
		if percent(a) < p.MixtureWeight {
			return lo + offset
		}
		return hi - offset
	case 3:
		return lo + (x+y)/2
	case 4:
		return lo + min(x, y)
	case 5:
		return lo + max(x, y)
	default:
		return lo + x
	}
}

func (f Framing) length(payload, padding int) int {
	return f.Envelope + max(f.MinimumPlaintext, f.PayloadPrefix+payload+padding)
}

// alignmentPadding finds the smallest reachable lattice target at or above the
// unpadded framed length. A failed target is skipped, never partially padded.
// Payload selection and its hard floor are independent of alignment feasibility.
func (f Framing) alignmentPadding(payload, allowance, grid, residue int) (int, bool) {
	base := f.length(payload, 0)
	target := base + (residue-base%grid+grid)%grid
	if target == base {
		return 0, true
	}
	padding := target - f.Envelope - f.PayloadPrefix - payload
	if padding > allowance {
		return 0, false
	}
	return padding, true
}

func (s *Shaper) nextEnhanced(available int) Decision {
	p := s.profile
	d := Decision{Batch: p.Batch}
	if available <= 0 {
		return d
	}
	payload, padding, align := s.fixedPayload, s.fixedPadding, s.fixedAlign
	if s.config.AutoJitter {
		var words [6]uint32
		for i := 0; i < 3; i++ {
			r := s.jitter.Uint64()
			words[2*i], words[2*i+1] = uint32(r), uint32(r>>32)
		}
		payload = sampleEnhanced(words[0], words[1], p.ChunkMin, p.ChunkMax, p.ChunkDistribution, p)
		padding = 0
		if percent(words[2]) < p.PaddingChance {
			padding = sampleEnhanced(words[3], words[4], 0, p.PaddingMax, p.PaddingDistribution, p)
		}
		align = percent(words[5]) < p.AlignmentChance
	}
	d.Payload = min(available, payload)
	if s.limits.PaddingPerSecond == 0 {
		return d
	}
	allowance := min(p.PaddingMax, d.Payload*p.PaddingRatioPermille/1000, s.limits.MaxPayload-d.Payload, int(s.tokens/1e9))
	padding = min(allowance, padding)
	if align {
		if aligned, ok := s.framing.alignmentPadding(d.Payload, allowance, p.AlignmentGrid, p.AlignmentResidue); ok {
			padding = aligned
		}
	}
	// Adapter minimum plaintext can make requested padding invisible. Do not
	// consume optional padding tokens when the resulting record length is equal.
	if s.framing.length(d.Payload, padding) > s.framing.length(d.Payload, 0) {
		d.Padding = padding
		s.tokens -= int64(padding) * 1e9
	}
	return d
}

package hydra

// DynamicV2Version separates this sender-only scheduling domain from domains1..5.
// Authenticated headers, protocol versions, encryption keys and nonces are unchanged.
const DynamicV2Version = 6

// NewDynamicV2 retains adaptive DATA shaping and samples optional PAD only from
// its currently feasible, visibly growing wire geometry. All calls require the
// caller's writer mutex. No waits, queues or additional padding credit are added.
func NewDynamicV2(config Config, protocol string, seed [32]byte, limits Limits, options TrafficOptions) (*Shaper, error) {
	return newTraffic(config, protocol, seed, limits, options, DynamicV2Version)
}

func (s *Shaper) deriveDynamicV2(epoch uint64) {
	s.deriveAdaptive(epoch)
	s.profile.AlgorithmVersion = DynamicV2Version
	s.adaptive.noise = noiseRun{}
}

// The uint8 position selects a cyclic displacement over the whole viable range,
// never a reduced upper bound. width<=1MiB and shifted<2*width make both arithmetic
// and a single conditional wrap safe even on 32-bit systems. This schedule state
// is not encryption material. Uniform-family support is preserved by the bijection.
func dynamicV2Offset(sample, minimum, maximum int, position uint8) int {
	width := maximum - minimum + 1
	offset := width * int(position) >> 8
	shifted := sample - minimum + offset
	if shifted >= width {
		shifted -= width
	}
	return minimum + shifted
}

// Advance once per geometrically feasible opportunity, including cadence/chance
// skips. Standalone renewals use only two random words: they need no grid/residue.
// Inline residues are initially chosen from a real, positively growing frame.
func (s *Shaper) advanceDynamicV2Noise(minimum, maximum, payload int, standalone bool) {
	n := &s.adaptive.noise
	if n.remaining == 0 {
		r := s.traffic.pad.Uint64()
		n.remaining = uint8(2 + scale(uint32(r), 15))
		n.family = uint8(scale(uint32(r>>32), 6))
		r = s.traffic.pad.Uint64()
		// Domain6 reuses intensity's storage for the complete 0..255 position.
		n.intensity = uint8(r)
		if !standalone {
			r = s.traffic.pad.Uint64()
			n.gridShift = uint8(4 + scale(uint32(r), 5))
			padding := minimum + scale(uint32(r>>32), maximum-minimum+1)
			n.residue = uint8(s.framing.length(payload, padding) & ((1 << n.gridShift) - 1))
		}
	}
	n.remaining--
}

// Unlike domain5, the caller has already established a nonempty feasible range.
// Cadence and chance parameters retain their established envelopes; only actual
// viable opportunities advance them. DATA uses its independent generator.
func (s *Shaper) dynamicV2Padding(minimum, maximum, payload int, standalone bool) (int, bool) {
	s.advanceDynamicV2Noise(minimum, maximum, payload, standalone)
	s.traffic.padPosition++
	if s.adaptive.padRemaining > 0 {
		s.adaptive.padRemaining--
		return 0, false
	}
	p := s.profile
	r := s.traffic.pad.Uint64()
	s.adaptive.padRemaining = sampleEnhanced(uint32(r), uint32(r>>32), p.PaddingGapMin, p.PaddingGapMax, p.PaddingGapDistribution, p) - 1
	r = s.traffic.pad.Uint64()
	a, b := uint32(r), uint32(r>>32)
	r = s.traffic.pad.Uint64()
	align := !standalone && percent(uint32(r)) < p.AlignmentChance
	if percent(uint32(r>>32)) >= p.PaddingChance {
		return 0, align
	}
	candidate := sampleEnhanced(a, b, minimum, maximum, int(s.adaptive.noise.family), p)
	return dynamicV2Offset(candidate, minimum, maximum, s.adaptive.noise.intensity), align
}

func (s *Shaper) nextDynamicV2(available int) Decision {
	p := s.profile
	d := Decision{Batch: p.Batch}
	if available <= 0 {
		return d
	}
	payload, batch := s.adaptivePayload()
	d.Payload, d.Batch = min(available, payload), batch
	if s.traffic.options.StandalonePaddingMinimum > 0 || s.limits.PaddingPerSecond == 0 {
		return d
	}
	maximum := min(p.PaddingMax, d.Payload*p.PaddingRatioPermille/1000, d.Payload/4, s.limits.MaxPayload-d.Payload, int(s.tokens/1e9))
	// The minimum plaintext floor can hide bytes. Start after that floor, not at
	// zero padding, so every accepted candidate really increases framed length.
	minimum := max(1, s.framing.MinimumPlaintext-s.framing.PayloadPrefix-d.Payload+1)
	if maximum < minimum {
		return d
	}
	padding, align := s.dynamicV2Padding(minimum, maximum, d.Payload, false)
	if align {
		n := s.adaptive.noise
		mask := (1 << n.gridShift) - 1
		base := s.framing.length(d.Payload, minimum)
		target := base + (int(n.residue)-base)&mask
		aligned := target - s.framing.Envelope - s.framing.PayloadPrefix - d.Payload
		if aligned >= minimum && aligned <= maximum {
			padding = aligned
		}
	}
	if padding > 0 {
		d.Padding = padding
		s.tokens -= int64(padding) * 1e9
	}
	return d
}

func (s *Shaper) nextDynamicV2Standalone(payload int) int {
	if s.limits.PaddingPerSecond == 0 {
		return 0
	}
	o := s.traffic.options
	minimum := o.StandalonePaddingMinimum
	maximum := min(s.profile.PaddingMax, 255, s.limits.MaxPadding, payload/4-o.StandalonePaddingEnvelope, int(s.tokens/1e9)-o.StandalonePaddingEnvelope)
	if maximum < minimum {
		return 0
	}
	padding, _ := s.dynamicV2Padding(minimum, maximum, payload, true)
	if padding > 0 {
		s.tokens -= int64(o.StandalonePaddingEnvelope+padding) * 1e9
	}
	return padding
}

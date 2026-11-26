package hydra

// DynamicVersion changes only the local sender derivation domain. It never
// changes an authenticated header, protocol version, key or nonce.
const DynamicVersion = 5

// On amd64 these five bytes reuse adaptiveState's alignment padding. Noise owns only
// PAD opportunities; DATA decisions continue using their separate generator.
type noiseRun struct {
	remaining uint8
	family    uint8
	gridShift uint8
	residue   uint8
	intensity uint8
}

// NewDynamic retains adaptive DATA shaping and adds bounded PAD noise runs.
// Inline runs vary framed-length alignment targets; standalone runs vary PAD
// size families and intensity within the original geometry and token limits.
// Fixed mode remains epoch-fixed. All operations require the writer mutex.
func NewDynamic(config Config, protocol string, seed [32]byte, limits Limits, options TrafficOptions) (*Shaper, error) {
	return newTraffic(config, protocol, seed, limits, options, DynamicVersion)
}

func (s *Shaper) deriveDynamic(epoch uint64) {
	s.deriveAdaptive(epoch)
	s.profile.AlgorithmVersion = DynamicVersion
	s.adaptive.noise = noiseRun{}
}

// Advance exactly once per valid PAD opportunity, including cadence skips.
// No elapsed-time loop, queue, additional generator or padding credit is added.
func (s *Shaper) advanceNoiseRun() {
	n := &s.adaptive.noise
	if n.remaining == 0 {
		r := s.traffic.pad.Uint64()
		n.remaining = uint8(2 + scale(uint32(r), 15))
		n.family = uint8(scale(uint32(r>>32), 6))
		r = s.traffic.pad.Uint64()
		n.gridShift = uint8(4 + scale(uint32(r), 5))
		n.residue = uint8(scale(uint32(r>>32), 1<<n.gridShift))
		r = s.traffic.pad.Uint64()
		n.intensity = uint8(25 + scale(uint32(r), 76))
	}
	n.remaining--
}

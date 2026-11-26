package hyrakenpro

import (
	"net"
	"time"

	"loft.local/trafficprofile"
)

// ChameleonProfileName identifies the Pro-local policy; it adds no wire fields.
const ChameleonProfileName = "hyraken-pro-chameleon-v1"

// NormalizeChameleonProfile owns a complete normalized clone. Only Pro's
// enabled DATA timing limit changes; identity, padding and TCP intent survive.
func NormalizeChameleonProfile(p *trafficprofile.Profile) (*trafficprofile.Profile, error) {
	out, err := trafficprofile.Normalize(p)
	if err != nil || out == nil {
		return out, err
	}
	if out.Timing != nil && out.Timing.Enabled {
		out.Timing.MaxDelayUS = min(out.Timing.MaxDelayUS, 250)
	}
	return out, nil
}

// WrapChameleonTCP bounds Pro's raw outgoing TCP prefix work before TLS.
// Shared engines continue to use their unchanged WrapTCP policy.
func WrapChameleonTCP(conn net.Conn, p *trafficprofile.Profile) net.Conn {
	return trafficprofile.WrapTCPWithBudget(conn, p, 64, 128)
}

// The writer owns this state. The shared sampler still decides imprint,
// padding and pressure behavior; Pro only suppresses excess positive pauses.
type chameleonSampler struct {
	base        trafficprofile.Sampler
	last        time.Time
	pauseTokens time.Duration
}

func newChameleonSampler(config trafficprofile.Timing, seed uint64) chameleonSampler {
	config.MaxDelayUS = min(max(config.MaxDelayUS, 0), 250)
	return chameleonSampler{base: trafficprofile.NewSampler(config, seed), pauseTokens: time.Second / 4}
}

func (s *chameleonSampler) Next(now time.Time, size int, backlogged bool) trafficprofile.Decision {
	out := s.base.Next(now, size, backlogged)
	if out.Delay <= 0 {
		return out
	}
	const pauseCost = time.Second / 8
	if !s.last.IsZero() {
		elapsed := min(max(now.Sub(s.last), 0), time.Second)
		s.pauseTokens = min(2*pauseCost, s.pauseTokens+elapsed)
	}
	s.last = now
	if s.pauseTokens < pauseCost {
		out.Delay = 0
	} else {
		s.pauseTokens -= pauseCost
	}
	// Suppressed/canceled waits conservatively retain the shared token charge.
	return out
}

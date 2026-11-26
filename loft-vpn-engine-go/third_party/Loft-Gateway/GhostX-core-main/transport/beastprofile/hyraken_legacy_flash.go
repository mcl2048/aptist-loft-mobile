package beastprofile

import "github.com/sagernet/quic-go/congestion"

// HyrakenLegacyFlashProfile pairs ordinary Hyraken's encrypted packet shells
// with their Beast sender's final ACK-compensated ceiling. Keep nominal startup
// and conservative Flash loss thresholds independent of that higher ceiling.
// This constructor grants no extra flight credit and is not selected by H3,
// fixed targets, Next, X or the independent Business sender.
func HyrakenLegacyFlashProfile(targetRate uint64, scenario string) (uint64, Profile) {
	target := max(uint64(1), min(targetRate, maxRate))
	paired := HyrakenProfile(scenario)
	// Match the paired sender's actual compensation arithmetic. Clamp before
	// conversion and before the ratio: even a saturated Beast gets 85%, rather
	// than letting both modes saturate at the same 20 Gbit/s ceiling.
	ceiling := uint64(min(float64(maxRate), float64(target)/paired.MinAckRate))
	p := HyrakenFlashProfile(target)
	p.maxPacingRate = congestion.ByteCount(max(uint64(1), ceiling*85/100))
	p.freshRounds, p.respondECN = true, true
	return ceiling, p
}

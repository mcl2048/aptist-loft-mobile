package beastprofile

import "time"

// HyrakenXAutoBeastProfile keeps the existing eager startup, loss tolerance,
// ACK-driven recovery and compensated ceiling. A scenario is not measured link
// capacity: sustained queue/CE/loss may retreat to 5 Mbit/s per physical sender.
// Idle/stale feedback cannot restore a previous high startup rate. Fixed-rate
// X and all legacy protocol constructors retain their existing policy.
func HyrakenXAutoBeastProfile(targetRate uint64, scenario string) (uint64, Profile) {
	rate, p := FixedRateProfile(targetRate, scenario)
	p.congestedMinRate = min(p.initialRate, 625_000)
	return rate, p
}

// HyrakenXFlashProfile starts at no more than 10 Mbit/s and lets sustained
// congestion retreat to 5 Mbit/s on an unknown-capacity path. X's existing loss
// thresholds, flight budget and paired 85% ceiling remain in force. Each
// growth/cut round consumes fresh outcomes once; idle cannot revive startup.
// This separate constructor leaves every legacy protocol's policy unchanged.
func HyrakenXFlashProfile(beastCeiling uint64) Profile {
	p := HyrakenFlashProfile(beastCeiling)
	p.initialRate = min(p.initialRate, 1_250_000)
	p.congestedMinRate = min(p.initialRate, 625_000)
	p.queueFloor = 5 * time.Millisecond
	p.freshRounds = true
	p.respondECN = true
	return p
}

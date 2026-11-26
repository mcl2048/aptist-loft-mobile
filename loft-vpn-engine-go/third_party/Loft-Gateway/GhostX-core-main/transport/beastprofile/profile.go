// Package beastprofile implements the bounded QUBF Beast QUIC sender.
package beastprofile

import (
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
	"github.com/sagernet/sing/common/logger"
)

const (
	HysteriaClientRate uint64               = 31_250_000 // 250 Mbps automatic target, decimal.
	HysteriaServerRate uint64               = 62_500_000 // 500 Mbps automatic target.
	TUICClientRate     uint64               = 31_250_000
	TUICServerRate     uint64               = 62_500_000
	maxRate            uint64               = 2_500_000_000 // 20 Gbps arithmetic ceiling, including compensation.
	maxInFlight        congestion.ByteCount = 8 << 20
)

// Profile is local policy, never a QUIC transport parameter or share credential.
// The RTT guard borrows BBR's separation of propagation delay and queue pressure;
// this rate-target sender is not an implementation of BBRv3 or its fairness model.
type Profile struct {
	MaxInFlight congestion.ByteCount
	MinAckRate  float64

	// Adaptive profiles recover only while acknowledged demand stays healthy
	// and never pace above maxPacingRate. An optional startupRate preserves an
	// explicitly declared target on a new connection.
	adaptive         bool
	initialRate      congestion.ByteCount
	startupRate      congestion.ByteCount // Optional first-connection burst; loss/idle still return to initialRate.
	congestedMinRate congestion.ByteCount // Optional lower floor for unknown-capacity Flash H3 paths.
	maxPacingRate    congestion.ByteCount
	maxTargetRate    congestion.ByteCount // Legacy protected shells retain their uncompensated target.
	queueFloor       time.Duration        // Ignore sub-millisecond packetizer/scheduler jitter for hybrid adaptation.
	lossTolerant     bool                 // Explicit lossy hybrid policy; Flash and other scenarios retain their thresholds.
	h3Ramp           bool                 // Faster ACK-driven steps, never a second packet queue.
	resilient        bool                 // Protected targets: moderate loss is not itself queue evidence.
	freshRounds      bool                 // Consume fresh outcomes once, without changing this profile's loss thresholds.
	respondECN       bool                 // The pinned QUIC reports validated CE through its zero-loss single callback.
}

func HyrakenProfile(scenario string) Profile {
	p := Profile{MaxInFlight: 24 << 20, MinAckRate: 0.5}
	if scenario == "lossy" {
		p.MinAckRate = 0.4
	}
	return p
}

// FixedRateProfile preserves eager nominal startup and bounded ACK/loss
// compensation. Queue pressure, validated CE, majority loss and stale feedback
// withdraw that pressure; fresh healthy ACKs can restore only the declared
// nominal target. QUIC still owns loss detection, retransmission and PTO.
// Callers retain their protocol's existing physical in-flight limit.
func FixedRateProfile(targetRate uint64, scenario string) (uint64, Profile) {
	target := max(uint64(1), min(targetRate, maxRate))
	ceiling := min(maxRate, target*2)
	p := HyrakenProfile(scenario)
	if scenario == "lossy" {
		ceiling = min(maxRate, target*5/2)
		p.lossTolerant = true
	}
	p.adaptive, p.h3Ramp, p.resilient, p.respondECN = true, true, true, true
	p.initialRate = max(1, congestion.ByteCount(target)/10)
	p.startupRate, p.maxTargetRate = congestion.ByteCount(target), congestion.ByteCount(target)
	p.maxPacingRate = congestion.ByteCount(ceiling)
	p.queueFloor = 5 * time.Millisecond
	return ceiling, p
}

// HyrakenFlashProfile keeps startup gentle and caps the final, compensated
// pacing rate at 85% of the automatic Beast target. The caller supplies that
// target in bytes per second so scenario policy remains owned by Hyraken.
func HyrakenFlashProfile(targetRate uint64) Profile {
	target := congestion.ByteCount(max(1, min(targetRate, maxRate)))
	p := Profile{
		MaxInFlight:   24 << 20,
		MinAckRate:    0.8,
		adaptive:      true,
		initialRate:   max(1, target/5),
		maxPacingRate: max(1, target*85/100),
	}
	return p
}

// HyrakenHybridProfile is local to the default hybrid record + genuine H3
// combination. It ramps from a smaller startup target and retreats to that
// target on a queued link. It owns no extra queue, worker or connection credit.
// Gemini NOTE: Flash retains its 85% ceiling; fixed-rate users stay on their
// existing explicit policy. These targets do not measure network capacity.
func HyrakenHybridProfile(targetRate uint64, flash bool, scenario string) Profile {
	p := HyrakenFlashProfile(targetRate)
	target := congestion.ByteCount(max(1, min(targetRate, maxRate)))
	if !flash {
		p.maxPacingRate = target
		if scenario == "lossy" {
			p.MinAckRate = 0.4
			p.lossTolerant = true
		}
	}
	p.initialRate = max(1, target/10)
	p.queueFloor = 5 * time.Millisecond
	return p
}

// HyrakenH3Profile links the three standard H3 shells to a bounded adaptive
// policy. A legacy static sender retains its original initial target, while
// an existing adaptive sender gets a 20% first-connection burst. Healthy ACKs
// may reach 125% of the scenario target; Flash's final compensated ceiling is
// 85% of that paired Beast ceiling. This is a policy ratio, not measured link
// capacity. Beast retains its 10% fallback; Flash starts at no more than
// 10 Mbps and can retreat to 5 Mbps without idle granting a fresh burst.
// The returned rate and policy must enter the same sender factory.
func HyrakenH3Profile(targetRate uint64, previous Profile, flash bool, scenario string) (uint64, Profile) {
	target := max(uint64(1), min(targetRate, maxRate))
	p := HyrakenHybridProfile(target, flash, scenario)
	p.h3Ramp = true
	p.startupRate = congestion.ByteCount(target)
	if previous.adaptive {
		p.startupRate = max(1, congestion.ByteCount(target)/5)
	}
	target = min(maxRate, target*5/4)
	p.maxPacingRate = congestion.ByteCount(target)
	if flash {
		p.maxPacingRate = max(1, p.maxPacingRate*85/100)
		// A scenario target is not measured access capacity. Keep the cold
		// H3 flight modest, and permit persistent queue/CE feedback to retreat
		// below startup. Healthy fresh ACKs still recover to the paired cap.
		p.initialRate = min(p.initialRate, 1_250_000) // 10 Mbps, decimal.
		p.startupRate = min(p.startupRate, 1_250_000)
		p.congestedMinRate = 625_000 // 5 Mbps; preserve large-flow loss/RTT-change deadlines.
		// Compensation history is not permission for another growth/cut round.
		// Keep ordinary Flash's conservative loss thresholds and existing floor;
		// Business selects its different thresholds through its own profile.
		p.freshRounds = true
	}
	return target, p
}

// HyrakenResilientProfile preserves each existing H3/Flash ceiling and gives
// legacy Rocca/KEM packet shells bounded retreat and recovery. Their initial
// target and maximum ACK compensation stay unchanged; healthy ACKs cannot
// increase the uncompensated target. Flash retains its gentle loss thresholds.
// Gemini NOTE：只作用于调用者选中的自动 Hyraken 画像，不改变密码、wire 或内存准入。
func HyrakenResilientProfile(targetRate uint64, previous Profile, flash bool) (uint64, Profile) {
	target := congestion.ByteCount(max(uint64(1), min(targetRate, maxRate)))
	p := previous
	p.resilient, p.respondECN = !flash, true
	if p.adaptive {
		return uint64(target), p
	}
	ackFloor := p.MinAckRate
	if !(ackFloor >= 0.4 && ackFloor <= 0.8) {
		ackFloor, p.MinAckRate = 0.5, 0.5
	}
	p.adaptive = true
	p.initialRate, p.startupRate, p.maxTargetRate = max(1, target/10), target, target
	p.maxPacingRate = congestion.ByteCount(min(float64(maxRate), float64(target)/ackFloor))
	p.queueFloor = 5 * time.Millisecond
	return uint64(p.maxPacingRate), p
}

// HyrakenAutomaticProfile separates unknown access capacity from the preset's
// startup target. Only the caller's automatic adaptive path selects this
// lower congested floor; fixed targets and existing Flash policy keep theirs.
func HyrakenAutomaticProfile(previous Profile) Profile {
	if previous.adaptive {
		previous.congestedMinRate = min(previous.initialRate, 625_000) // 5 decimal Mbit/s, per physical sender.
	}
	return previous
}

// Sender has one owner: QUIC's send loop. ACK/loss outcomes are counted once in
// Ex; QUIC retains loss detection, retransmission, PTO and flow control. The
// protected Hyraken profiles consume validated ECN-CE once per marked flight;
// positive-loss single callbacks remain empty to avoid counting loss twice.
// No packet queue, worker, per-packet allocation or speculative ACK is added.
type Sender struct {
	rtt                   congestion.RTTStatsProvider
	rate, mss             congestion.ByteCount
	profile               Profile
	pacer                 beastPacer
	slots                 [5]feedbackSlot
	recentSlots           [5]feedbackSlot // Resilient/lossy H3 growth uses 100ms buckets; compensation keeps 5s history.
	roundGood, roundBad   uint64          // Fresh outcomes, consumed once per protected decision round.
	roundSamples          uint64
	lastSentPacket        congestion.PacketNumber
	ceRecoveryEnd         congestion.PacketNumber // Only ACKs beyond the marked flight can restore growth.
	ceBoundaryValid       bool
	cePending, ceRecovery bool
	ackRate               float64
	lastACK, lastFeedback monotime.Time
	lastRateChange        monotime.Time
	lastRateChangeValid   bool
	lastSend              monotime.Time // Adaptive only: distinguish record production gaps from idle restart.
	appLimited            bool
	demand                bool
	blocked               bool
	healthySince          monotime.Time
	queueSince            monotime.Time // Hybrid only: sustained queue, not one scheduler spike.
	debug                 bool
	log                   logger.Logger
	lastDebug             monotime.Time
}

type feedbackSlot struct {
	second             int64
	good, bad, samples uint64
	valid              bool
}

var _ congestion.CongestionControlEx = (*Sender)(nil)

func New(rate uint64, packetSize congestion.ByteCount) *Sender {
	return NewWithDebug(rate, packetSize, false, nil)
}

func NewWithDebug(rate uint64, packetSize congestion.ByteCount, debug bool, log logger.Logger) *Sender {
	// TUIC and HY2 use this entry point. Keep their nominal targets and 8 MiB
	// flight budget while withdrawing compensation on congestion evidence.
	ceiling, p := FixedRateProfile(rate, "bulk")
	p.MaxInFlight = maxInFlight
	return NewWithProfile(ceiling, packetSize, p, debug, log)
}

func NewWithProfile(rate uint64, packetSize congestion.ByteCount, p Profile, debug bool, log logger.Logger) *Sender {
	// Validate before signed conversion. A zero rate must not divide the pacer by zero.
	if p.MaxInFlight < 12000 || p.MaxInFlight > 24<<20 {
		p.MaxInFlight = maxInFlight
	}
	if !(p.MinAckRate >= 0.4 && p.MinAckRate <= 0.8) {
		p.MinAckRate = 0.5
	}
	boundedRate := congestion.ByteCount(max(1, min(rate, maxRate)))
	if p.adaptive {
		// Keep malformed or mismatched local policy fail-closed. In particular,
		// neither ACK compensation nor a bad profile can raise this hard ceiling.
		p.maxPacingRate = max(1, min(p.maxPacingRate, boundedRate))
		if p.maxTargetRate != 0 {
			p.maxTargetRate = max(1, min(p.maxTargetRate, p.maxPacingRate))
		}
		ceiling := p.maxPacingRate
		if p.maxTargetRate != 0 {
			ceiling = p.maxTargetRate
		}
		p.initialRate = max(1, min(p.initialRate, ceiling))
		if p.congestedMinRate != 0 {
			p.congestedMinRate = max(1, min(p.congestedMinRate, p.initialRate))
		}
		if p.startupRate != 0 {
			p.startupRate = max(p.initialRate, min(p.startupRate, ceiling))
		}
	}
	s := &Sender{rate: boundedRate, profile: p, ackRate: 1, debug: debug, log: log}
	if p.adaptive {
		s.rate = p.initialRate
		if p.startupRate != 0 {
			s.rate = p.startupRate
		}
	}
	s.mss = max(1200, min(packetSize, p.MaxInFlight/10))
	s.pacer = beastPacer{mss: s.mss, rate: s.pacingRate}
	return s
}

func (s *Sender) SetRTTStatsProvider(rtt congestion.RTTStatsProvider) { s.rtt = rtt }
func (s *Sender) TimeUntilSend(congestion.ByteCount) monotime.Time    { return s.pacer.next() }
func (s *Sender) HasPacingBudget(at monotime.Time) bool {
	s.expire(at)
	return s.pacer.budget(at) >= s.mss
}
func (s *Sender) CanSend(inFlight congestion.ByteCount) bool {
	return inFlight >= 0 && inFlight < s.GetCongestionWindow()
}
func (s *Sender) GetCongestionWindow() congestion.ByteCount {
	minimum := 10 * s.mss
	if s.rtt == nil || s.rtt.SmoothedRTT() <= 0 {
		return minimum
	}
	// Clamp in floating point before converting to signed ByteCount (extreme RTT).
	// Queue growth may not grant ever larger windows: use propagation RTT while
	// blocked, with the same connection hard cap as the previous release.
	rtt := s.rtt.SmoothedRTT()
	if s.blocked && s.rtt.MinRTT() > 0 {
		rtt = min(rtt, s.rtt.MinRTT())
	}
	window := float64(s.pacingRate()) * rtt.Seconds() * 2
	return congestion.ByteCount(min(float64(s.profile.MaxInFlight), max(float64(minimum), window)))
}
func (s *Sender) pacingRate() congestion.ByteCount {
	ack := s.ackRate
	if s.blocked || s.ceRecovery {
		ack = 1
	} // Queue pressure and validated CE both cancel extra loss compensation.
	rate := min(float64(maxRate), float64(s.rate)/ack)
	if s.profile.adaptive {
		rate = min(rate, float64(s.profile.maxPacingRate))
	}
	return congestion.ByteCount(rate)
}

// CurrentPacingRate and PacingRateLimit expose local sender diagnostics; they
// do not report measured path capacity or a throughput guarantee.
func (s *Sender) CurrentPacingRate() congestion.ByteCount { return s.pacingRate() }

func (s *Sender) PacingRateLimit() congestion.ByteCount {
	return s.profile.maxPacingRate
}

func (s *Sender) congestionFloor() congestion.ByteCount {
	if s.profile.congestedMinRate > 0 {
		return s.profile.congestedMinRate
	}
	return s.profile.initialRate
}

func (s *Sender) expire(at monotime.Time) {
	if s.profile.adaptive && s.appLimited && s.lastSend != 0 {
		// QUIC's callback can follow a ~1ms empty packetizer. That is common
		// between AEAD records, not evidence of a new application burst.
		// Preserve the stage for at most 1 RTT (200ms..1s), then reset before
		// granting another pacing budget. ACK-only traffic cannot extend it.
		idle := 200 * time.Millisecond
		if s.rtt != nil {
			idle = min(time.Second, max(idle, s.rtt.SmoothedRTT()))
		}
		if at < s.lastSend || at.Sub(s.lastSend) >= idle {
			s.resetAdaptive()
		}
	}
	ttl := time.Second
	if s.rtt != nil {
		ttl = min(10*time.Second, max(ttl, 3*min(s.rtt.SmoothedRTT(), 3*time.Second)))
	}
	if s.lastFeedback != 0 && (at.Sub(s.lastFeedback) > ttl || s.lastACK == 0 || at.Sub(s.lastACK) > ttl) {
		s.ackRate = 1
		clear(s.slots[:])
		clear(s.recentSlots[:])
		s.roundGood, s.roundBad, s.roundSamples = 0, 0, 0
		s.lastACK, s.lastFeedback, s.healthySince = 0, 0, 0
		s.queueSince = 0
		if s.profile.adaptive {
			// Expired feedback cannot authorize another startup burst.
			s.rate = s.congestionFloor()
			s.demand = false
			s.lastRateChange, s.lastRateChangeValid = 0, false
		}
	}
}
func (s *Sender) OnPacketSent(at monotime.Time, _ congestion.ByteCount, number congestion.PacketNumber, size congestion.ByteCount, ackEliciting bool) {
	s.expire(at)
	if s.profile.respondECN && ackEliciting && size > 0 {
		s.lastSentPacket = max(s.lastSentPacket, number)
	}
	if s.profile.adaptive && ackEliciting {
		s.demand = true
		s.lastSend, s.appLimited = at, false
	}
	s.pacer.sent(at, size)
}
func (*Sender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}
func (s *Sender) OnCongestionEvent(number congestion.PacketNumber, lost, inFlight congestion.ByteCount) {
	// In the locked QUIC, zero bytes means validated ECN-CE; real packet
	// losses have a positive size and are counted exclusively by Ex below.
	// Keep a packet boundary, not an ACK-count heuristic: a marked flight
	// cuts only once even when its ACKs arrive across multiple callbacks.
	if !s.profile.respondECN || lost != 0 || inFlight <= 0 || number < 0 ||
		(s.ceBoundaryValid && number <= s.ceRecoveryEnd) {
		return
	}
	s.cePending, s.ceRecovery, s.ceBoundaryValid = true, true, true
	s.ceRecoveryEnd = max(s.lastSentPacket, number)
}
func (s *Sender) OnCongestionEventEx(_ congestion.ByteCount, at monotime.Time, acked []congestion.AckedPacketInfo, lost []congestion.LostPacketInfo) {
	marked := s.cePending
	s.expire(at)
	if marked {
		// The single callback has no receive timestamp. Consume its signal
		// here, on the same QUIC owner, before growth or compensation. An
		// idle reset cannot erase a CE that just arrived with this ACK batch.
		s.cePending, s.ceRecovery = false, true
		s.rate = max(s.congestionFloor(), s.rate*3/4)
		s.lastRateChange, s.lastRateChangeValid = at, true
		s.roundGood, s.roundBad, s.roundSamples = 0, 0, 0
	}
	var good, bad, samples uint64
	for _, p := range acked {
		if p.BytesAcked > 0 {
			if !marked && p.PacketNumber > s.ceRecoveryEnd {
				s.ceRecovery = false
			}
			good += uint64(min(p.BytesAcked, 65536))
			samples++
		}
	}
	for _, p := range lost {
		if p.BytesLost > 0 {
			bad += uint64(min(p.BytesLost, 65536))
			samples++
		}
	}
	if samples == 0 {
		return
	}
	if (s.profile.resilient || s.profile.freshRounds) && samples <= 1<<32-s.roundSamples {
		// Same sample/byte bound as a feedback bucket. ACK grouping may split
		// a round across callbacks; no slice, timer or packet queue is retained.
		s.roundGood += good
		s.roundBad += bad
		s.roundSamples += samples
	}
	hasACK := good > 0
	s.lastFeedback = at
	if hasACK {
		s.lastACK = at
	}
	recentGood, recentBad, recentSamples := good, bad, samples
	good, bad, samples = recordFeedback(&s.slots, int64(time.Duration(at)/time.Second), good, bad, samples)
	if s.profile.resilient || s.profile.freshRounds || s.profile.h3Ramp && s.profile.lossTolerant {
		// A recovered link must not keep cutting its target because of losses
		// several seconds ago. Count real outcomes over 400..500ms for this
		// policy's growth/retreat only. The original compensation history,
		// queue guard, one-step-per-RTT and final hard ceilings stay independent.
		recentGood, recentBad, recentSamples = recordFeedback(&s.recentSlots, int64(time.Duration(at)/(100*time.Millisecond)), recentGood, recentBad, recentSamples)
	} else {
		recentGood, recentBad, recentSamples = good, bad, samples
	}
	s.ackRate = 1
	if samples >= 50 && good > 0 {
		s.ackRate = max(s.profile.MinAckRate, float64(good)/float64(good+bad))
	}
	s.updateQueueGuard(at, hasACK)
	if s.profile.adaptive {
		ackRatio := 1.0
		if total := recentGood + recentBad; total > 0 {
			ackRatio = float64(recentGood) / float64(total)
		}
		s.updateAdaptiveRate(at, hasACK, recentSamples, ackRatio)
	}
	if s.debug && s.log != nil && at.Sub(s.lastDebug) >= 2*time.Second {
		s.lastDebug = at
		s.log.Debug("[beast] target_bytes_per_second=", s.rate, " pacing_bytes_per_second=", s.pacingRate(), " ack_ratio=", s.ackRate, " queue_guard=", s.blocked)
	}
}

// Fixed storage and the original per-bucket byte/sample bounds apply to both
// time scales. Future buckets are ignored, including after a clock rollback.
func recordFeedback(slots *[5]feedbackSlot, tick int64, good, bad, samples uint64) (uint64, uint64, uint64) {
	index := (tick%5 + 5) % 5
	slot := &slots[index]
	if !slot.valid || slot.second != tick {
		*slot = feedbackSlot{second: tick, valid: true}
	}
	// Reject an oversized batch rather than partially count its ACK/loss ratio.
	if samples <= 1<<32-slot.samples {
		slot.good += good
		slot.bad += bad
		slot.samples += samples
	}
	good, bad, samples = 0, 0, 0
	for _, slot := range slots {
		if age := tick - slot.second; slot.valid && age >= 0 && age < 5 {
			good += slot.good
			bad += slot.bad
			samples += slot.samples
		}
	}
	return good, bad, samples
}

func (s *Sender) updateAdaptiveRate(at monotime.Time, hasACK bool, samples uint64, ackRatio float64) {
	if !s.profile.adaptive || !s.demand {
		return
	}
	// Limit changes to one per RTT. Without a trustworthy RTT, do not climb.
	if s.rtt == nil || s.rtt.SmoothedRTT() <= 0 {
		return
	}
	interval := max(20*time.Millisecond, s.rtt.SmoothedRTT())
	if s.lastRateChangeValid && at.Sub(s.lastRateChange) < interval {
		return
	}

	// Queue growth or sustained loss cuts the current rate multiplicatively.
	// The independent ACK compensation remains capped by pacingRate above.
	queued := s.blocked
	if s.profile.queueFloor > 0 {
		queued = queued && s.queueSince != 0 && at.Sub(s.queueSince) >= max(100*time.Millisecond, 2*s.rtt.MinRTT())
	}
	cutRatio, growRatio := 0.9, 0.95
	if s.profile.resilient {
		// Protected bulk/speedtest can recover with 65% actual byte delivery
		// on an unqueued link. Below 55% still cuts the target;
		// neither threshold changes the compensation or physical ceilings.
		cutRatio, growRatio = 0.55, 0.65
	}
	if s.profile.lossTolerant {
		// Retain the pre-existing hybrid policy outside protected target
		// profiles. Explicit protected lossy tolerates 45% loss when fresh ACKs
		// show no queue; majority loss below 45% delivery still retreats.
		cutRatio, growRatio = 0.5, 0.6
		if s.profile.resilient {
			cutRatio, growRatio = 0.45, 0.55
		}
	}
	severeLoss := samples >= 50 && ackRatio < cutRatio
	growthHasACK := hasACK
	if s.profile.resilient || s.profile.freshRounds {
		// A 400..500ms growth history must not turn one old loss burst into
		// several fresh bad RTTs. Consume only newly reported outcomes for
		// retreat, retaining the independent recent-growth and 5s compensation
		// windows. Queue/CE still revoke acceleration through their own paths.
		// A low-rate flight may report fewer than 50 outcomes per RTT. Keep
		// that bounded evidence across callbacks/RTTs until a decision has
		// enough fresh samples; resetting it every RTT hides sustained loss.
		// Growth consumes the same fresh round, so old clean ACKs cannot grant
		// repeated increases. Queue pressure remains immediately actionable;
		// Expiry, idle, the compatibility timeout hook and CE discard evidence
		// through their owners; actual QUIC PTO does not call that hook.
		if !queued && s.roundSamples < 50 {
			return
		}
		total := s.roundGood + s.roundBad
		roundRatio := 0.0
		if total > 0 {
			roundRatio = float64(s.roundGood) / float64(total)
		}
		severeLoss = s.roundSamples >= 50 && total > 0 && roundRatio < cutRatio
		// A fresh round may finish in a loss-only callback after its ACKs.
		// Consume that round's real ACK evidence once, within the same RTT,
		// rather than making growth depend on callback ordering. Loss alone
		// cannot refresh lastACK or revive an old/ACK-free decision round.
		growthHasACK = s.roundGood > 0 && roundRatio >= growRatio && s.lastACK != 0 && at >= s.lastACK && at.Sub(s.lastACK) <= interval
		// Sparse XHTTP uploads may need more than the 500ms history to collect
		// 50 outcomes. Use the completed fresh round for sample admission;
		// both its delivery ratio and the recent ratio must still allow growth.
		// No old ACK, larger ceiling or additional send credit is introduced.
		samples = s.roundSamples
		s.roundGood, s.roundBad, s.roundSamples = 0, 0, 0
		s.lastRateChange, s.lastRateChangeValid = at, true
	}
	if queued || severeLoss {
		next := max(s.congestionFloor(), s.rate*3/4)
		if next < s.rate {
			s.rate = next
			s.lastRateChange, s.lastRateChangeValid = at, true
		}
		return
	}
	if s.blocked || s.ceRecovery {
		return // A transient queue may freeze growth without forcing a rate cut.
	}
	// Require a healthy, fresh ACK window before each step. Genuine H3 and
	// protected fixed targets recover by 50%; legacy profiles retain 25%.
	if !growthHasACK || samples < 50 || ackRatio < growRatio {
		return
	}
	step := s.rate / 4
	if s.profile.h3Ramp {
		step = s.rate / 2
	}
	ceiling := s.profile.maxPacingRate
	if s.profile.maxTargetRate != 0 {
		ceiling = s.profile.maxTargetRate
	}
	s.rate = min(ceiling, s.rate+max(1, step))
	s.lastRateChange, s.lastRateChangeValid = at, true
}

// An empty packetizer suppresses growth immediately. It does not prove idle:
// encrypted-record production and flow control can leave short scheduling gaps.
// expire resets a genuinely idle adaptive stage before the next pacing decision.
func (s *Sender) OnAppLimited(congestion.ByteCount) {
	if !s.profile.adaptive {
		return
	}
	s.demand = false
	s.appLimited = true
}

func (s *Sender) resetAdaptive() {
	s.cePending, s.ceRecovery = false, false
	s.demand, s.appLimited, s.lastSend = false, false, 0
	if s.profile.congestedMinRate > 0 {
		// Application idle and the compatibility timeout hook provide no new
		// capacity evidence. Preserve a prior retreat until healthy ACKs
		// permit growth; profiles without a lower floor keep their contract.
		s.rate = min(s.rate, s.profile.initialRate)
	} else {
		s.rate = s.profile.initialRate
	}
	s.ackRate = 1
	clear(s.slots[:])
	clear(s.recentSlots[:])
	s.roundGood, s.roundBad, s.roundSamples = 0, 0, 0
	s.lastACK, s.lastFeedback, s.healthySince = 0, 0, 0
	s.queueSince = 0
	s.lastRateChange, s.lastRateChangeValid = 0, false
}

func (s *Sender) updateQueueGuard(at monotime.Time, hasACK bool) {
	if s.rtt == nil || s.rtt.MinRTT() <= 0 || s.rtt.LatestRTT() <= 0 || s.rtt.SmoothedRTT() <= 0 {
		s.blocked, s.healthySince = true, 0
		return
	}
	minimum := s.rtt.MinRTT()
	latest := max(s.rtt.LatestRTT(), s.rtt.SmoothedRTT())
	if s.profile.queueFloor > 0 {
		if latest-minimum < s.profile.queueFloor {
			// A tiny baseline makes normal local scheduling look like a large
			// relative queue. Require both a relative and absolute queue signal.
			latest = minimum
			s.queueSince = 0
		} else if float64(latest)/float64(minimum) >= 1.25 {
			if s.queueSince == 0 || at < s.queueSince {
				s.queueSince = at
			}
		} else {
			s.queueSince = 0
		}
	}
	if float64(latest)/float64(minimum) >= 1.25 {
		s.blocked, s.healthySince = true, 0
	} else if s.blocked {
		if !hasACK || float64(latest)/float64(minimum) > 1.125 {
			s.healthySince = 0
		} else if s.healthySince == 0 {
			s.healthySince = at
		} else if at.Sub(s.healthySince) >= max(s.rtt.SmoothedRTT(), 10*time.Millisecond) {
			s.blocked, s.healthySince = false, 0
		}
	}
}
func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	if size < 1200 {
		return
	}
	s.mss = min(size, s.profile.MaxInFlight/10)
	s.pacer.mss = s.mss
}
func (*Sender) InSlowStart() bool                        { return false }
func (s *Sender) InRecovery() bool                       { return s.ceRecovery }
func (*Sender) MaybeExitSlowStart()                      {}
func (*Sender) OnPacketNeutered(congestion.PacketNumber) {}
func (*Sender) OnPacketsLost(congestion.PacketNumber)    {}
func (s *Sender) OnRetransmissionTimeout(retransmitted bool) {
	if retransmitted {
		s.ackRate = 1
		clear(s.slots[:])
		clear(s.recentSlots[:])
		s.roundGood, s.roundBad, s.roundSamples = 0, 0, 0
		s.lastACK, s.lastFeedback, s.healthySince = 0, 0, 0
		s.queueSince = 0
		if s.profile.adaptive {
			s.resetAdaptive()
		}
	}
}

// NextXHTTPProfile is exclusive to Next v2/v3's genuine H3 packet-up carrier.
// The shared Hyraken factories and their parameters stay byte-for-byte intact.
// Unknown access capacity starts at no more than 10 Mbps and may retreat to
// 5 Mbps per physical sender. Fresh healthy demand can recover the unchanged
// scenario ceiling; queue, ECN, loss and idle still withdraw that pressure.
func NextXHTTPProfile(targetRate uint64, flash bool, scenario string) Profile {
	target := congestion.ByteCount(max(uint64(1), min(targetRate, maxRate)))
	p := Profile{MaxInFlight: 8 << 20, MinAckRate: 0.5, adaptive: true,
		initialRate: min(max(1, target/10), 1_250_000), startupRate: min(max(1, target/5), 1_250_000),
		maxPacingRate: target, maxTargetRate: target, queueFloor: 5 * time.Millisecond,
		h3Ramp: true, resilient: !flash, respondECN: true}
	p.congestedMinRate = min(p.initialRate, 625_000)
	if scenario == "lossy" {
		p.MinAckRate = 0.4
		p.lossTolerant = true
	}
	if flash {
		p.freshRounds = true
		p.maxPacingRate = max(1, target*85/100)
		p.maxTargetRate = p.maxPacingRate
		p.MinAckRate = 0.8
	}
	return p
}

// NextFixedRateProfile preserves Next's declared nominal startup and its old
// 2x compensated ceiling, including lossy. Queue, validated CE, majority loss
// and stale demand can retreat; healthy fresh ACKs restore only the nominal
// target. The existing shared sender owns these transitions, not a new queue.
func NextFixedRateProfile(targetRate uint64) (uint64, Profile) {
	rate, p := FixedRateProfile(targetRate, "bulk")
	p.MaxInFlight = 8 << 20
	return rate, p
}

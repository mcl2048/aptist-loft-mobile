package net.aptist.loft.service

import java.util.concurrent.atomic.AtomicReference

/** One attempt's cached facts. No I/O or business-state decision occurs here. */
class GoSnapshotAdmission {
    private val facts = AtomicReference<GoVpnFacts?>(null)
    private var leftStartup = false
    private var terminalObserved = false
    private var closedJoined = false
    private var readyJoined = false

    // Compare and commit together: a captured callback can finish decoding after
    // direct Ready/Close, but cannot overwrite their newer lifecycle floor.
    @Synchronized fun observe(candidate: GoVpnFacts): Boolean {
        val previous = facts.get()
        if (previous != null && candidate.generation < previous.generation) return false
        if (closedJoined && !candidate.provesReleased) return false
        if (leftStartup && candidate.state in setOf(GoVpnState.IDLE, GoVpnState.STARTING)) return false
        if (readyJoined && candidate.state == GoVpnState.RUNNING && candidate.ownershipPending) return false
        val terminal = candidate.state in setOf(GoVpnState.BLOCKED, GoVpnState.FAILED, GoVpnState.UNAVAILABLE,
            GoVpnState.STOPPING, GoVpnState.STOPPED, GoVpnState.CLOSED)
        if (terminalObserved && !terminal) return false
        if (previous?.state == GoVpnState.STARTING && candidate.state == GoVpnState.IDLE) return false
        if (candidate.state !in setOf(GoVpnState.IDLE, GoVpnState.STARTING)) leftStartup = true
        if (terminal) terminalObserved = true
        if (candidate.provesReleased) closedJoined = true
        if (candidate.provesReady) readyJoined = true
        facts.set(candidate)
        return true
    }
    fun current(): GoVpnFacts? = facts.get()

    companion object {
        fun requiresFault(candidate: GoVpnFacts, expected: CapturedNetworkPolicy): Boolean = candidate.generation !in 0L..1L ||
            (candidate.privacy.policyInstalled && !candidate.privacy.samePolicy(expected)) ||
            // Go can install/publish the real session before Start's outer
            // ownership joins. Only a matching pending startup may wait; a
            // settled Running frame still requires the complete actual proof.
            (candidate.state == GoVpnState.RUNNING && (candidate.generation != 1L || !candidate.privacy.samePolicy(expected) ||
                (!candidate.ownershipPending && !candidate.provesReady)))
    }
}

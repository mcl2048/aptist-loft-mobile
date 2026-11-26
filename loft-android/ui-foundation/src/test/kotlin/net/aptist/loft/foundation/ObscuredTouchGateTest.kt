package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class ObscuredTouchGateTest {
    private data class Event(val action: Int, val flags: Int)
    private fun clicks(gate: ObscuredTouchGate, vararg events: Event): Int {
        var pressed = false
        var clicks = 0
        for (event in events) when (gate.decide(event.action, event.flags)) {
            TouchDispatch.CANCEL_AND_CONSUME -> pressed = false
            TouchDispatch.CONSUME -> Unit
            TouchDispatch.PASS -> when (event.action) {
                0 -> pressed = true
                1 -> { if (pressed) clicks++; pressed = false }
                3 -> pressed = false
            }
        }
        return clicks
    }
    @Test fun fullyObscuredDownCannotActivateASecretControlWithACleanUp() {
        val gate = ObscuredTouchGate().also { it.setSensitive(true) }
        assertEquals(0, clicks(gate, Event(0, 1), Event(1, 0)))
    }
    @Test fun partiallyObscuredDownCannotActivateASecretControl() {
        val gate = ObscuredTouchGate().also { it.setSensitive(true) }
        assertEquals(0, clicks(gate, Event(0, 2), Event(1, 0)))
    }
    @Test fun midGestureObscurationCancelsAnAcceptedDownAndConsumesTheRemainder() {
        val gate = ObscuredTouchGate().also { it.setSensitive(true) }
        assertEquals(TouchDispatch.PASS, gate.decide(0, 0))
        assertEquals(TouchDispatch.CANCEL_AND_CONSUME, gate.decide(2, 2))
        assertEquals(TouchDispatch.CONSUME, gate.decide(1, 0))
    }
    @Test fun fullyObscuredMoveCannotLeaveAPressedSecretControlArmed() {
        val gate = ObscuredTouchGate().also { it.setSensitive(true) }
        assertEquals(0, clicks(gate, Event(0, 0), Event(2, 1), Event(1, 0)))
    }
    @Test fun aFreshCleanGestureAfterABlockedGestureStillWorks() {
        val gate = ObscuredTouchGate().also { it.setSensitive(true) }
        assertEquals(1, clicks(gate, Event(0, 2), Event(1, 0), Event(0, 0), Event(1, 0)))
    }
    @Test fun cleanSensitiveAndNormalPageGesturesRemainUsable() {
        val gate = ObscuredTouchGate().also { it.setSensitive(true) }
        assertEquals(1, clicks(gate, Event(0, 0), Event(1, 0)))
        gate.setSensitive(false)
        assertEquals(1, clicks(gate, Event(0, 3), Event(1, 3)))
    }
    @Test fun scopeAndLifecycleResetDoNotKeepTheNextPageBlocked() {
        val gate = ObscuredTouchGate().also { it.setSensitive(true) }
        assertEquals(0, clicks(gate, Event(0, 1), Event(1, 0)))
        gate.reset(); gate.setSensitive(false)
        assertEquals(1, clicks(gate, Event(0, 0), Event(1, 0)))
    }
}

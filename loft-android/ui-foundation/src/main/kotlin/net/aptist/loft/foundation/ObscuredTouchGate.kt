package net.aptist.loft.foundation

enum class TouchDispatch { PASS, CONSUME, CANCEL_AND_CONSUME }

/** Gesture admission only; scope and actual MotionEvent/window APIs stay Android. */
class ObscuredTouchGate {
    private var sensitive = false
    private var admitted = false
    private var rejected = false

    fun setSensitive(value: Boolean) {
        if (sensitive != value) reset()
        sensitive = value
    }
    fun reset() { admitted = false; rejected = false }

    fun decide(action: Int, flags: Int): TouchDispatch {
        if (!sensitive) return TouchDispatch.PASS
        val obscured = flags and OBSCURED_FLAGS != 0
        val terminal = action == UP || action == CANCEL
        if (action == DOWN) {
            reset()
            rejected = obscured
            admitted = !obscured
            return if (obscured) TouchDispatch.CONSUME else TouchDispatch.PASS
        }
        if (rejected) {
            if (terminal) reset()
            return TouchDispatch.CONSUME
        }
        if (obscured) {
            val dispatch = if (admitted) TouchDispatch.CANCEL_AND_CONSUME else TouchDispatch.CONSUME
            admitted = false
            rejected = !terminal
            return dispatch
        }
        if (terminal) reset()
        return TouchDispatch.PASS
    }

    private companion object {
        // Public Android MotionEvent action/flag values; this module stays JVM-only.
        const val DOWN = 0
        const val UP = 1
        const val CANCEL = 3
        const val OBSCURED_FLAGS = 1 or 2
    }
}

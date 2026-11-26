package net.aptist.loft.foundation

class VisibilityEpoch {
    private var epoch = 0L
    private var active = false
    @Synchronized fun begin(): Long {
        epoch = Math.addExact(epoch, 1L)
        active = true
        return epoch
    }
    @Synchronized fun end() { active = false }
    @Synchronized fun accepts(ticket: Long): Boolean = active && ticket == epoch
}

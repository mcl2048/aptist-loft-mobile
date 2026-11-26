package net.aptist.loft.foundation

/** Retained UI draft for a single OS permission result; Rust validates it later. */
class VpnPermissionDraft {
    private var pending: CoreCommand.Connect? = null
    private var cancelled = false
    fun request(nodeId: String, generation: ULong): Boolean {
        if (pending != null) return false
        pending = CoreCommand.Connect(nodeId, generation)
        cancelled = false
        return true
    }
    fun cancel() { cancelled = true }
    fun finish(granted: Boolean): CoreCommand.Connect? {
        val draft = pending
        pending = null
        val accepted = granted && !cancelled
        cancelled = false
        return if (accepted) draft else null
    }
}

package net.aptist.loft.foundation

/** Strict transport-publication admission, independent of Rust generations. */
class SnapshotSequence {
    private var activeBinding: Long? = null
    private var newest: ULong? = null
    @Synchronized fun begin(binding: Long) { activeBinding = binding; newest = null }
    @Synchronized fun end() { activeBinding = null; newest = null }
    @Synchronized fun accepts(binding: Long, publicationSequence: ULong): Boolean {
        if (activeBinding != binding || newest?.let { publicationSequence <= it } == true) return false
        newest = publicationSequence
        return true
    }
}

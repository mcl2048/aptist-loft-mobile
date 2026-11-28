package net.aptist.loft.ui.notes

internal enum class NotesSwipeAction { ARCHIVE, DELETE }

internal fun notesSwipeAction(offset: Float, width: Int): NotesSwipeAction? {
    if (width <= 0) return null
    val scaledOffset = offset.toDouble() * 5
    val threshold = width.toDouble() * 3
    return when {
        scaledOffset >= threshold -> NotesSwipeAction.ARCHIVE
        scaledOffset <= -threshold -> NotesSwipeAction.DELETE
        else -> null
    }
}

package net.aptist.loft.ui.notes

import kotlin.math.abs
import kotlin.math.sin

internal const val NOTE_TAG_CHIP_HEIGHT = 48f

internal data class TagPosition(val x: Float, val y: Float)
internal data class TagWallLayout(val chipWidth: Float, val height: Float, val items: List<TagPosition>)

/** One finite expansion. Small bounded pushes prevent neighbors from remaining overlapped. */
internal fun noteTagWall(width: Float, count: Int, phase: Float): TagWallLayout {
    if (count == 0) return TagWallLayout(0f, 0f, emptyList())
    val gap = 8f
    val columns = when {
        width >= 432f -> 4
        width >= 252f -> 3
        width >= 166f -> 2
        else -> 1
    }.coerceAtMost(count)
    val rows = (count + columns - 1) / columns
    val chipWidth = ((width - gap * (columns - 1)) / columns).coerceAtMost(144f)
    val rowStep = NOTE_TAG_CHIP_HEIGHT + gap
    val height = rowStep * (rows - 1) + NOTE_TAG_CHIP_HEIGHT
    val center = TagPosition((width - chipWidth) / 2, (height - NOTE_TAG_CHIP_HEIGHT) / 2)
    val targets = (0 until count).map { index ->
        val row = index / columns
        val total = minOf(columns, count - row * columns)
        val rowWidth = total * chipWidth + (total - 1) * gap
        TagPosition((width - rowWidth) / 2 + (chipWidth + gap) * (index % columns), row * rowStep)
    }.sortedBy { cell ->
        val dx = cell.x - center.x
        val dy = cell.y - center.y
        dx * dx + dy * dy
    }
    if (phase >= 1f) return TagWallLayout(chipWidth, height, targets)
    val travel = 1f - (1f - phase) * (1f - phase)
    val drift = sin(phase * Math.PI).toFloat() * 13f
    val moving = targets.mapIndexed { index, cell ->
        TagPosition(center.x + (cell.x - center.x) * travel + drift * sin(index * 2.4f),
            center.y + (cell.y - center.y) * travel + drift * sin(index * 1.8f))
    }.toMutableList()
    if (phase > 0f) {
        repeat(3) {
            for (i in moving.indices) for (j in 0 until i) {
                val a = moving[i]
                val b = moving[j]
                val xOverlap = chipWidth - abs(a.x - b.x)
                val yOverlap = NOTE_TAG_CHIP_HEIGHT - abs(a.y - b.y)
                if (xOverlap > 0f && yOverlap > 0f) {
                    val separation = minOf(xOverlap, yOverlap) * phase * 0.32f
                    val push = if (xOverlap < yOverlap) TagPosition(if (a.x >= b.x) separation else -separation, 0f)
                    else TagPosition(0f, if (a.y >= b.y) separation else -separation)
                    moving[i] = TagPosition(a.x + push.x, a.y + push.y)
                    moving[j] = TagPosition(b.x - push.x, b.y - push.y)
                }
            }
        }
    }
    return TagWallLayout(chipWidth, height,
        moving.map { TagPosition(it.x.coerceIn(0f, width - chipWidth), it.y.coerceIn(0f, height - NOTE_TAG_CHIP_HEIGHT)) })
}

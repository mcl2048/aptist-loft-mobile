package net.aptist.loft.foundation

enum class FoldAxis { VERTICAL, HORIZONTAL }
data class FoldRegion(val start: Float, val end: Float, val axis: FoldAxis,
    val separating: Boolean = true, val occluding: Boolean = true, val halfOpened: Boolean = false)
data class Viewport(val width: Float, val height: Float, val fontScale: Float = 1f, val fold: FoldRegion? = null,
    val additionalFolds: List<FoldRegion> = emptyList())
enum class LayoutMode { SINGLE, TWO_COLUMNS, TABLETOP }
data class PaneBounds(val left: Float, val top: Float, val right: Float, val bottom: Float) {
    val width get() = (right - left).coerceAtLeast(0f)
    val height get() = (bottom - top).coerceAtLeast(0f)
}
data class AdaptiveLayout(val mode: LayoutMode, val railWidth: Float, val primary: PaneBounds,
    val secondary: PaneBounds? = null, val horizontalRailGap: ClosedFloatingPointRange<Float>? = null, val railLeft: Float = 0f)
object AdaptiveLayoutPolicy {
    fun measure(viewport: Viewport): AdaptiveLayout {
        val width = viewport.width.takeIf { it.isFinite() }?.coerceAtLeast(1f) ?: 1f
        val height = viewport.height.takeIf { it.isFinite() }?.coerceAtLeast(1f) ?: 1f
        val font = viewport.fontScale.takeIf { it.isFinite() }?.coerceIn(1f, 1.4f) ?: 1f
        val rail = (if (width >= 600f) 72f else if (width < 360f) 48f else 56f).coerceAtMost(width)
        val minimumPane = 240f * font
        val folds = (listOfNotNull(viewport.fold) + viewport.additionalFolds.take(1)).filter {
            it.start.isFinite() && it.end.isFinite() && (it.separating || it.occluding || it.halfOpened && it.axis == FoldAxis.HORIZONTAL)
        }
        val vertical = folds.filter { it.axis == FoldAxis.VERTICAL }.filter { maxOf(it.start, it.end) > 0f && minOf(it.start, it.end) < width }
        if (vertical.isNotEmpty()) return measureVertical(width, height, rail, minimumPane, vertical)
        val fold = folds.firstOrNull { it.axis == FoldAxis.HORIZONTAL }
        if (fold != null) {
            val limit = if (fold.axis == FoldAxis.VERTICAL) width else height
            var start = minOf(fold.start, fold.end).coerceIn(0f, limit)
            var end = maxOf(fold.start, fold.end).coerceIn(0f, limit)
            if (start < limit && end > 0f) {
                if (start == end) { start = (start - 8f).coerceAtLeast(0f); end = (end + 8f).coerceAtMost(limit) }
                val top = PaneBounds(rail, 0f, width, start)
                val bottom = PaneBounds(rail, end, width, height)
                return if (top.height >= 160f * font && bottom.height >= 160f * font) {
                    AdaptiveLayout(LayoutMode.TABLETOP, rail, top, bottom, start..end)
                } else AdaptiveLayout(LayoutMode.SINGLE, rail, if (top.height >= bottom.height) top else bottom,
                    horizontalRailGap = start..end)
            }
        }
        val available = (width - rail).coerceAtLeast(0f)
        if (width >= 600f && available >= minimumPane * 2f + 16f) {
            val firstWidth = ((available - 16f) / 2f).coerceAtMost(520f)
            return AdaptiveLayout(LayoutMode.TWO_COLUMNS, rail, PaneBounds(rail, 0f, rail + firstWidth, height),
                PaneBounds(rail + firstWidth + 16f, 0f, width, height))
        }
        return AdaptiveLayout(LayoutMode.SINGLE, rail, PaneBounds(rail, 0f, width, height))
    }

    private fun measureVertical(width: Float, height: Float, nominalRail: Float, minimumPane: Float, folds: List<FoldRegion>): AdaptiveLayout {
        var intervals = listOf(0f to width)
        for (fold in folds.sortedBy { minOf(it.start, it.end) }) {
            var start = minOf(fold.start, fold.end).coerceIn(0f, width)
            var end = maxOf(fold.start, fold.end).coerceIn(0f, width)
            if (start == end) { start = (start - 8f).coerceAtLeast(0f); end = (end + 8f).coerceAtMost(width) }
            intervals = intervals.flatMap { (left, right) ->
                if (end <= left || start >= right) listOf(left to right)
                else buildList {
                    if (start > left) add(left to start)
                    if (end < right) add(end to right)
                }
            }
        }
        val railArea = intervals.firstOrNull { it.second - it.first >= nominalRail }
            ?: intervals.maxByOrNull { it.second - it.first } ?: (width to width)
        val railWidth = nominalRail.coerceAtMost((railArea.second - railArea.first).coerceAtLeast(0f))
        val railLeft = railArea.first
        val areas = intervals.map { (left, right) ->
            PaneBounds(if (left == railLeft) left + railWidth else left, 0f, right, height)
        }
        val candidates = areas.filter { it.width >= minimumPane }
        if (width >= 600f && candidates.size >= 2) {
            return AdaptiveLayout(LayoutMode.TWO_COLUMNS, railWidth, candidates[0], candidates[1], railLeft = railLeft)
        }
        val primary = candidates.maxByOrNull { it.width } ?: areas.maxByOrNull { it.width } ?: PaneBounds(width, 0f, width, height)
        if (primary.width >= 600f && primary.width >= minimumPane * 2f + 16f) {
            val firstWidth = ((primary.width - 16f) / 2f).coerceAtMost(520f)
            return AdaptiveLayout(LayoutMode.TWO_COLUMNS, railWidth, primary.copy(right = primary.left + firstWidth),
                primary.copy(left = primary.left + firstWidth + 16f), railLeft = railLeft)
        }
        return AdaptiveLayout(LayoutMode.SINGLE, railWidth, primary, railLeft = railLeft)
    }
}
data class PresentationState(
    val navigation: NavigationState = NavigationState(),
    val routingDraft: RoutingDraft? = null,
    val selectedNodeId: String? = null,
    val selectedAppPackage: String? = null,
    val layout: AdaptiveLayout = AdaptiveLayout(LayoutMode.SINGLE, 56f, PaneBounds(56f, 0f, 390f, 844f)),
) {
    fun resize(viewport: Viewport): PresentationState {
        val measured = AdaptiveLayoutPolicy.measure(viewport)
        return if (layout == measured) this else copy(layout = measured)
    }
}

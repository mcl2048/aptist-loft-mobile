package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class AdaptiveLayoutTest {
    // Catches using a physical device size instead of the actual resized window.
    @Test fun outerScreensStaySingleAndUnfoldedWindowsUseTwoColumns() {
        val cases = listOf(320f to LayoutMode.SINGLE, 390f to LayoutMode.SINGLE,
            600f to LayoutMode.TWO_COLUMNS, 673f to LayoutMode.TWO_COLUMNS,
            768f to LayoutMode.TWO_COLUMNS, 840f to LayoutMode.TWO_COLUMNS, 1440f to LayoutMode.TWO_COLUMNS)
        for ((width, expected) in cases) {
            val result = AdaptiveLayoutPolicy.measure(Viewport(width, 900f))
            assertEquals("window width $width", expected, result.mode)
            assertTrue(result.primary.width >= 240f)
            assertTrue(result.primary.right <= width)
        }
    }

    // Catches controls or reading content spanning an occluding vertical hinge.
    @Test fun verticalHingeDefinesTwoActualPanes() {
        val result = AdaptiveLayoutPolicy.measure(Viewport(673f, 900f, fold = FoldRegion(334f, 339f, FoldAxis.VERTICAL)))
        assertEquals(LayoutMode.TWO_COLUMNS, result.mode)
        assertEquals(72f, result.primary.left, 0.01f)
        assertEquals(334f, result.primary.right, 0.01f)
        assertEquals(339f, result.secondary!!.left, 0.01f)
        assertEquals(673f, result.secondary.right, 0.01f)
    }

    @Test fun narrowHingeSideUsesTheLargerSafeSinglePane() {
        val result = AdaptiveLayoutPolicy.measure(Viewport(673f, 900f, fold = FoldRegion(100f, 112f, FoldAxis.VERTICAL)))
        assertEquals(LayoutMode.SINGLE, result.mode)
        assertEquals(112f, result.primary.left, 0.01f)
        assertEquals(673f, result.primary.right, 0.01f)
    }

    // Catches tabletop posture treated as a regular wide rectangle.
    @Test fun tabletopUsesTopAndBottomRegionsWithoutTheHinge() {
        val result = AdaptiveLayoutPolicy.measure(Viewport(840f, 900f,
            fold = FoldRegion(430f, 446f, FoldAxis.HORIZONTAL, halfOpened = true)))
        assertEquals(LayoutMode.TABLETOP, result.mode)
        assertEquals(430f, result.primary.bottom, 0.01f)
        assertEquals(446f, result.secondary!!.top, 0.01f)
        assertEquals(900f, result.secondary.bottom, 0.01f)
    }

    // Catches a split layout with unreadably narrow controls at large system fonts.
    @Test fun largeFontsFallBackWhenTwoReadingPanesDoNotFit() {
        assertEquals(LayoutMode.SINGLE, AdaptiveLayoutPolicy.measure(Viewport(600f, 900f, fontScale = 2f)).mode)
        assertEquals(LayoutMode.TWO_COLUMNS, AdaptiveLayoutPolicy.measure(Viewport(840f, 900f, fontScale = 2f)).mode)
    }

    @Test fun foldBoundsAreClampedToTheCurrentSplitWindow() {
        val result = AdaptiveLayoutPolicy.measure(Viewport(390f, 600f,
            fold = FoldRegion(900f, 940f, FoldAxis.VERTICAL)))
        assertEquals(LayoutMode.SINGLE, result.mode)
        assertEquals(56f, result.primary.left, 0.01f)
        assertEquals(390f, result.primary.right, 0.01f)
        assertTrue(result.primary.width >= 0f)
    }

    // Catches a hinge entering the navigation area during window movement.
    @Test fun aHingeInsideTheRailMovesNavigationIntoASafeRegion() {
        val result = AdaptiveLayoutPolicy.measure(Viewport(673f, 900f, fold = FoldRegion(20f, 30f, FoldAxis.VERTICAL)))
        assertEquals(30f, result.railLeft, 0.01f)
        assertEquals(102f, result.primary.left, 0.01f)
        assertTrue(result.primary.right <= 673f)
        assertTrue(result.secondary == null || result.secondary.left >= 30f)
    }

    // Catches selecting a pane that crosses a second reported physical hinge.
    @Test fun everyReportedVerticalHingeIsExcludedFromReadingPanes() {
        val result = AdaptiveLayoutPolicy.measure(Viewport(1000f, 900f,
            fold = FoldRegion(260f, 266f, FoldAxis.VERTICAL), additionalFolds = listOf(FoldRegion(520f, 526f, FoldAxis.VERTICAL))))
        assertEquals(LayoutMode.TWO_COLUMNS, result.mode)
        assertEquals(266f, result.primary.left, 0.01f)
        assertEquals(520f, result.primary.right, 0.01f)
        assertEquals(526f, result.secondary!!.left, 0.01f)
    }

    // Catches resize handlers resetting drafts, route or selected items on fold/unfold.
    @Test fun unfoldAndRefoldPreserveTheUserDraftAndSelection() {
        val draft = RoutingDraft.from(false, emptySet()).withEnabled(true)
        val initial = PresentationState(navigation = NavigationState(page = Page.ROUTING),
            routingDraft = draft, selectedNodeId = "node-17", selectedAppPackage = "net.example.alpha")
        val unfolded = initial.resize(Viewport(673f, 900f))
        val refolded = unfolded.resize(Viewport(390f, 900f))
        assertEquals(LayoutMode.TWO_COLUMNS, unfolded.layout.mode)
        assertEquals(LayoutMode.SINGLE, refolded.layout.mode)
        assertEquals(Page.ROUTING, refolded.navigation.page)
        assertEquals("node-17", refolded.selectedNodeId)
        assertEquals("net.example.alpha", refolded.selectedAppPackage)
        assertSame(draft, refolded.routingDraft)
    }
}

package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class RoutingDraftTest {
    private val visible = listOf(
        VisibleApp("net.example.alpha", "Alpha", 11001),
        VisibleApp("net.example.alpha.helper", "Alpha helper", 11001),
        VisibleApp("net.example.beta", "Beta", 11002),
    )

    // Catches allowing two apps in one UID to claim different VPN routes.
    @Test fun sharedUidAppsAreSelectedAndDeselectedTogether() {
        val selected = RoutingDraft.from(false, emptySet()).toggle(visible, "net.example.alpha")
        assertEquals(setOf("net.example.alpha", "net.example.alpha.helper"), selected.selectedPackages)
        assertTrue(selected.toggle(visible, "net.example.alpha.helper").selectedPackages.isEmpty())
    }

    // Catches sending an empty allowed-app list, which Android would treat as all apps.
    @Test fun enabledEmptySelectionCannotBeSubmitted() {
        val draft = RoutingDraft.from(false, emptySet()).withEnabled(true)
        assertEquals(DraftProblem.EMPTY_SELECTION, (draft.submission(visible) as RoutingSubmission.Invalid).problem)
    }

    // Catches applying an app that disappeared after the picker was opened.
    @Test fun disappearedPackageBlocksSubmissionWithoutChangingDraft() {
        val draft = RoutingDraft.from(false, emptySet()).withEnabled(true).toggle(visible, "net.example.beta")
        val result = draft.submission(visible.filterNot { it.packageName == "net.example.beta" })
        assertEquals(DraftProblem.APP_UNAVAILABLE, (result as RoutingSubmission.Invalid).problem)
        assertEquals(setOf("net.example.beta"), draft.selectedPackages)
    }

    @Test fun unchangedDraftDoesNotEmitACommand() {
        assertSame(RoutingSubmission.Unchanged, RoutingDraft.from(true, setOf("net.example.beta")).submission(visible))
    }

    @Test fun savingProducesADraftCommandWithoutMutatingItsBaseline() {
        val baseline = RoutingDraft.from(false, emptySet())
        val draft = baseline.withEnabled(true).toggle(visible, "net.example.beta")
        val command = (draft.submission(visible) as RoutingSubmission.Ready).command
        assertTrue(command.enabled)
        assertEquals(listOf("net.example.beta"), command.packageNames)
        assertFalse(baseline.enabled)
        assertTrue(baseline.selectedPackages.isEmpty())
    }

    // Catches unbounded picker pages and search that ignores package names.
    @Test fun catalogReturnsBoundedPagesFromVisibleScope() {
        val rows = (1..120).map { VisibleApp("net.example.app$it", "App $it", 12000 + it) }
        val catalog = AppCatalog(rows)
        assertEquals(50, catalog.page("", emptySet(), false, 0).size)
        assertEquals(20, catalog.page("", emptySet(), false, 100).size)
        assertEquals(listOf("net.example.app120"), catalog.page("app120", emptySet(), false, 0).map { it.packageName })
        assertEquals(listOf("net.example.app7"), catalog.page("", setOf("net.example.app7"), true, 0).map { it.packageName })
    }
}

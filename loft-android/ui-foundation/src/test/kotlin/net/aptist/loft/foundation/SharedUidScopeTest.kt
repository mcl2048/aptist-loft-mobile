package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class SharedUidScopeTest {
    private val alpha = VisibleApp("net.example.alpha", "Alpha", 11001)
    private val helper = VisibleApp("net.example.alpha.helper", "Alpha helper", 11001)
    private val beta = VisibleApp("net.example.beta", "Beta", 11002)
    private fun members(uid: Int) = when (uid) { 11001 -> listOf(alpha, helper); 11002 -> listOf(beta); else -> emptyList() }

    // Catches a launcher-only query silently omitting a UID-sharing package.
    @Test fun pickerExpandsAllReportedUidPeers() {
        val rows = SharedUidScope.catalog(listOf(alpha, beta), ::members)
        assertEquals(setOf("net.example.alpha", "net.example.alpha.helper", "net.example.beta"), rows.map { it.packageName }.toSet())
        assertEquals(setOf("net.example.alpha", "net.example.alpha.helper"),
            RoutingDraft.from(false, emptySet()).toggle(rows, "net.example.alpha").selectedPackages)
    }

    // Catches Builder routing only a displayed subset while claiming other UID peers direct.
    @Test fun effectiveBuilderSelectionIncludesEveryUidPeer() {
        assertEquals(listOf("net.example.alpha", "net.example.alpha.helper"),
            SharedUidScope.effective(listOf("net.example.alpha"), { if (it == alpha.packageName) alpha else null }, ::members))
    }

    @Test fun missingSelectedPackageIsRejectedBeforeBuilder() {
        expect(ScopeProblem.UNAVAILABLE_APP) { SharedUidScope.effective(listOf("net.example.gone"), { null }, ::members) }
    }

    @Test fun incompleteOrMismatchedUidGroupIsRejected() {
        expect(ScopeProblem.INCOMPLETE_UID_GROUP) { SharedUidScope.catalog(listOf(alpha)) { emptyList() } }
        expect(ScopeProblem.INCOMPLETE_UID_GROUP) { SharedUidScope.catalog(listOf(alpha)) { listOf(alpha, beta) } }
    }

    @Test fun oversizedGroupIsRejectedWithoutPartialRouting() {
        val many = (1..101).map { VisibleApp("net.example.member$it", "Member $it", 11001) }
        expect(ScopeProblem.SELECTION_TOO_LARGE) { SharedUidScope.effective(listOf(alpha.packageName), { alpha }) { listOf(alpha) + many } }
    }

    @Test fun emptyEnabledSelectionIsRejectedBeforeBuilder() {
        expect(ScopeProblem.EMPTY_SELECTION) { SharedUidScope.effective(emptyList(), { null }, ::members) }
    }

    // Reject the platform-reported quota before visiting denied UID entries.
    @Test fun oversizedUidGroupIsRejectedBeforeItsMembersAreRead() {
        val denied = object : AbstractList<VisibleApp>() {
            override val size = 1001
            override fun get(index: Int): VisibleApp = throw AssertionError("Denied UID group was iterated")
        }
        expect(ScopeProblem.SELECTION_TOO_LARGE) {
            SharedUidScope.effective(listOf(alpha.packageName), { alpha }) { denied }
        }
    }

    @Test fun oversizedSelectionIsRejectedBeforePackageLookup() {
        expect(ScopeProblem.SELECTION_TOO_LARGE) {
            SharedUidScope.effective(List(101) { "net.example.app$it" },
                { throw AssertionError("Denied selection was queried") }, ::members)
        }
    }

    private fun expect(problem: ScopeProblem, work: () -> Unit) {
        try { work(); fail("Expected $problem") } catch (failure: AppScopeException) { assertEquals(problem, failure.problem) }
    }
}

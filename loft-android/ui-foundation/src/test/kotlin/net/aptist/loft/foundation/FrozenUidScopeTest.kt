package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class FrozenUidScopeTest {
    private val owner = 10042
    private val alpha = VisibleApp("net.example.alpha", "Alpha", 11001)
    private val helper = VisibleApp("net.example.alpha.helper", "Helper", 11001)
    private val names = listOf(alpha.packageName, helper.packageName)
    private fun lookup(name: String) = listOf(alpha, helper).firstOrNull { it.packageName == name }
    private fun members(uid: Int) = if (uid == alpha.uid) listOf(alpha, helper) else emptyList()

    // Same names with a reassigned UID must not preserve an already frozen scope.
    @Test fun captureBindsOwnerAndEveryActualUidWithImmutablePairs() {
        val mutableNames = names.reversed().toMutableList()
        val scope = FrozenUidScope.capture(owner, true, mutableNames, ::lookup, ::members)
        mutableNames.clear()
        assertEquals(owner, scope.vpnOwnerUid)
        assertEquals(listOf(PackageUidIdentity(alpha.packageName, 11001), PackageUidIdentity(helper.packageName, 11001)), scope.packageUids)
        try { (scope.packageUids as MutableList<PackageUidIdentity>).clear(); fail("MUTABLE_SCOPE_IDENTITY") }
        catch (_: UnsupportedOperationException) { }
    }

    @Test fun sameNamesWithDifferentUidCannotMatchFrozenIdentity() {
        val scope = FrozenUidScope.capture(owner, true, names, ::lookup, ::members)
        val reassigned = listOf(alpha.copy(uid = 11007), helper.copy(uid = 11007))
        assertFalse(FrozenUidScope.matches(scope, owner, true, names,
            { name -> reassigned.firstOrNull { it.packageName == name } }, { reassigned }))
    }

    @Test fun fullProfileScopeStillBindsTheActualOwner() {
        val scope = FrozenUidScope.capture(owner, false, emptyList(),
            { throw AssertionError("FULL_SCOPE_LOOKUP") }, { throw AssertionError("FULL_SCOPE_LOOKUP") })
        assertTrue(scope.packageUids.isEmpty())
        assertTrue(FrozenUidScope.matches(scope, owner, false, emptyList(), ::lookup, ::members))
        assertFalse(FrozenUidScope.matches(scope, owner + 100000, false, emptyList(), ::lookup, ::members))
    }

    @Test fun zeroOwnerUidCannotFreezeAFullScope() {
        expect(ScopeProblem.INCOMPLETE_UID_GROUP) {
            FrozenUidScope.capture(0, false, emptyList(),
                { throw AssertionError("INVALID_OWNER_LOOKUP") }, { throw AssertionError("INVALID_OWNER_LOOKUP") })
        }
    }

    @Test fun zeroPackageUidCannotFreezeASelectedScope() {
        val invalidApp = alpha.copy(uid = 0)
        expect(ScopeProblem.INCOMPLETE_UID_GROUP) {
            FrozenUidScope.capture(owner, true, listOf(invalidApp.packageName),
                { invalidApp }, { listOf(invalidApp) })
        }
    }

    @Test fun missingOrNewSharedUidPeerInvalidatesFrozenCoverage() {
        expect(ScopeProblem.INCOMPLETE_UID_GROUP) {
            FrozenUidScope.capture(owner, true, listOf(alpha.packageName), ::lookup, ::members)
        }
        val scope = FrozenUidScope.capture(owner, true, names, ::lookup, ::members)
        val newPeer = VisibleApp("net.example.peer", "Peer", alpha.uid)
        assertFalse(FrozenUidScope.matches(scope, owner, true, names, ::lookup) { listOf(alpha, helper, newPeer) })
    }

    @Test fun disappearedPackageAndForeignProfileAreRejected() {
        expect(ScopeProblem.UNAVAILABLE_APP) {
            FrozenUidScope.capture(owner, true, names, { null }, ::members)
        }
        expect(ScopeProblem.INCOMPLETE_UID_GROUP) {
            FrozenUidScope.capture(owner + 100000, true, names, ::lookup, ::members)
        }
    }

    @Test fun contradictoryFullScopeAndDuplicateNamesAreRejected() {
        expect(ScopeProblem.INCOMPLETE_UID_GROUP) {
            FrozenUidScope.capture(owner, false, names, ::lookup, ::members)
        }
        expect(ScopeProblem.INCOMPLETE_UID_GROUP) {
            FrozenUidScope.capture(owner, true, listOf(alpha.packageName, alpha.packageName), ::lookup, ::members)
        }
    }

    @Test fun deniedQuotaIsRejectedBeforeReadingOrLookingUpNames() {
        val denied = object : AbstractList<String>() {
            override val size = 101
            override fun get(index: Int): String = throw AssertionError("DENIED_SCOPE_ITERATED")
        }
        expect(ScopeProblem.SELECTION_TOO_LARGE) {
            FrozenUidScope.capture(owner, true, denied,
                { throw AssertionError("DENIED_SCOPE_LOOKUP") }, { throw AssertionError("DENIED_SCOPE_LOOKUP") })
        }
    }

    private fun expect(problem: ScopeProblem, work: () -> Unit) {
        try { work(); fail("SCOPE_MUST_BE_REJECTED") }
        catch (failure: AppScopeException) { assertEquals(problem, failure.problem) }
    }
}

package net.aptist.loft.foundation

import java.util.Collections

data class PackageUidIdentity(val packageName: String, val uid: Int)
@ConsistentCopyVisibility
data class PlatformUidScope internal constructor(val vpnOwnerUid: Int, val packageUids: List<PackageUidIdentity>)

/** Mechanical platform identity only; Rust freezes its authoritative scope ID. */
object FrozenUidScope {
    fun capture(vpnOwnerUid: Int, enabled: Boolean, packages: List<String>,
        lookup: (String) -> VisibleApp?, members: (Int) -> List<VisibleApp>): PlatformUidScope {
        if (vpnOwnerUid <= 0) invalid()
        if (packages.size > 100) throw AppScopeException(ScopeProblem.SELECTION_TOO_LARGE)
        if (!enabled) {
            if (packages.isNotEmpty()) invalid()
            return PlatformUidScope(vpnOwnerUid, emptyList())
        }
        val sorted = packages.sorted()
        if (sorted.distinct().size != sorted.size) invalid()
        if (SharedUidScope.effective(sorted, lookup, members) != sorted) invalid()
        val pairs = sorted.map { name ->
            val app = lookup(name) ?: throw AppScopeException(ScopeProblem.UNAVAILABLE_APP)
            if (app.packageName != name || app.uid <= 0 || app.uid / 100000 != vpnOwnerUid / 100000) invalid()
            PackageUidIdentity(name, app.uid)
        }
        pairs.groupBy { it.uid }.forEach { (uid, expected) ->
            val actual = members(uid)
            if (actual.size > 100) throw AppScopeException(ScopeProblem.SELECTION_TOO_LARGE)
            if (actual.any { it.uid != uid } || actual.map { it.packageName }.toSet() != expected.map { it.packageName }.toSet()) invalid()
        }
        return PlatformUidScope(vpnOwnerUid, Collections.unmodifiableList(ArrayList(pairs)))
    }

    fun matches(frozen: PlatformUidScope, vpnOwnerUid: Int, enabled: Boolean, packages: List<String>,
        lookup: (String) -> VisibleApp?, members: (Int) -> List<VisibleApp>): Boolean = try {
        frozen == capture(vpnOwnerUid, enabled, packages, lookup, members)
    } catch (_: AppScopeException) { false }

    private fun invalid(): Nothing = throw AppScopeException(ScopeProblem.INCOMPLETE_UID_GROUP)
}

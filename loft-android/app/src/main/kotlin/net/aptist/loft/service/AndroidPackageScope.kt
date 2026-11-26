package net.aptist.loft.service

import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import net.aptist.loft.foundation.AppScopeException
import net.aptist.loft.foundation.ScopeProblem
import net.aptist.loft.foundation.SharedUidScope
import net.aptist.loft.foundation.VisibleApp
import net.aptist.loft.foundation.FrozenUidScope
import net.aptist.loft.foundation.PlatformUidScope

class AndroidPackageScope(context: Context) {
    private val manager = context.applicationContext.packageManager
    private val user = Process.myUid() / 100000

    fun visibleCatalog(): List<VisibleApp> {
        @Suppress("DEPRECATION") val installed = manager.getInstalledApplications(0)
        if (installed.size > 1000) throw AppScopeException(ScopeProblem.CATALOG_TOO_LARGE)
        val visible = installed.filter { it.uid / 100000 == user }.map { info ->
            VisibleApp(info.packageName, manager.getApplicationLabel(info).toString().take(128), info.uid)
        }
        return SharedUidScope.catalog(visible) { members(it, 1000, ScopeProblem.CATALOG_TOO_LARGE) }
    }

    fun effectivePackages(requested: List<String>): List<String> = SharedUidScope.effective(requested, ::lookup) {
        members(it, 100, ScopeProblem.SELECTION_TOO_LARGE)
    }

    fun freezeIdentity(enabled: Boolean, packages: List<String>): PlatformUidScope =
        FrozenUidScope.capture(Process.myUid(), enabled, packages, ::lookup) { members(it, 100, ScopeProblem.SELECTION_TOO_LARGE) }

    fun matchesIdentity(frozen: PlatformUidScope, enabled: Boolean, packages: List<String>): Boolean =
        FrozenUidScope.matches(frozen, Process.myUid(), enabled, packages, ::lookup) { members(it, 100, ScopeProblem.SELECTION_TOO_LARGE) }

    private fun lookup(packageName: String): VisibleApp? {
        return try {
            @Suppress("DEPRECATION") val info = manager.getApplicationInfo(packageName, 0)
            if (info.uid / 100000 != user) null else VisibleApp(info.packageName,
                manager.getApplicationLabel(info).toString().take(128), info.uid)
        } catch (_: PackageManager.NameNotFoundException) { null }
    }

    private fun members(uid: Int, limit: Int, problem: ScopeProblem): List<VisibleApp> {
        val names = manager.getPackagesForUid(uid) ?: throw AppScopeException(ScopeProblem.INCOMPLETE_UID_GROUP)
        if (names.size > limit) throw AppScopeException(problem)
        return names.map { name -> lookup(name) ?: throw AppScopeException(ScopeProblem.INCOMPLETE_UID_GROUP) }
    }
}

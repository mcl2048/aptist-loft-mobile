package net.aptist.loft.foundation

data class VisibleApp(val packageName: String, val label: String, val uid: Int)
enum class DraftProblem { EMPTY_SELECTION, APP_UNAVAILABLE, TOO_MANY_APPS }
sealed interface RoutingSubmission {
    data object Unchanged : RoutingSubmission
    data class Invalid(val problem: DraftProblem) : RoutingSubmission
    data class Ready(val command: CoreCommand.SetRouting) : RoutingSubmission
}

@ConsistentCopyVisibility
data class RoutingDraft private constructor(
    val enabled: Boolean,
    val selectedPackages: Set<String>,
    private val initialEnabled: Boolean,
    private val initialPackages: Set<String>,
) {
    val dirty: Boolean get() = enabled != initialEnabled || selectedPackages != initialPackages
    fun withEnabled(value: Boolean): RoutingDraft = copy(enabled = value)
    fun toggle(visible: List<VisibleApp>, packageName: String): RoutingDraft {
        val app = visible.find { it.packageName == packageName }
        val group = if (app == null) setOf(packageName) else visible.filter { it.uid == app.uid }.map { it.packageName }.toSet()
        val selection = if (packageName in selectedPackages) selectedPackages - group else if (app != null) selectedPackages + group else selectedPackages
        return copy(selectedPackages = selection.toSet())
    }
    fun submission(visible: List<VisibleApp>): RoutingSubmission {
        if (!dirty) return RoutingSubmission.Unchanged
        if (selectedPackages.size > 100) return RoutingSubmission.Invalid(DraftProblem.TOO_MANY_APPS)
        if (enabled && selectedPackages.isEmpty()) return RoutingSubmission.Invalid(DraftProblem.EMPTY_SELECTION)
        if (enabled && selectedPackages.any { selected -> visible.none { it.packageName == selected } }) {
            return RoutingSubmission.Invalid(DraftProblem.APP_UNAVAILABLE)
        }
        return RoutingSubmission.Ready(CoreCommand.SetRouting(enabled, selectedPackages.sorted()))
    }
    companion object {
        fun from(enabled: Boolean, packages: Set<String>) = RoutingDraft(enabled, packages.toSet(), enabled, packages.toSet())
    }
}

class AppCatalog(rows: List<VisibleApp>) {
    private val entries = rows.distinctBy { it.packageName }.sortedWith(compareBy<VisibleApp> { it.label.lowercase(java.util.Locale.ROOT) }.thenBy { it.packageName })
    fun page(query: String, selected: Set<String>, selectedOnly: Boolean, offset: Int): List<VisibleApp> {
        require(offset >= 0)
        return entries.asSequence().filter { !selectedOnly || it.packageName in selected }
            .filter { query.isBlank() || it.label.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true) }
            .drop(offset).take(50).toList()
    }
}

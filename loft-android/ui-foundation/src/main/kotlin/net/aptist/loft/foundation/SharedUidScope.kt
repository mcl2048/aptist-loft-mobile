package net.aptist.loft.foundation

enum class ScopeProblem { UNAVAILABLE_APP, INCOMPLETE_UID_GROUP, SELECTION_TOO_LARGE, CATALOG_TOO_LARGE, EMPTY_SELECTION }
class AppScopeException(val problem: ScopeProblem) : IllegalArgumentException(problem.name)
object SharedUidScope {
    fun catalog(visible: List<VisibleApp>, members: (Int) -> List<VisibleApp>): List<VisibleApp> {
        if (visible.size > 1000) throw AppScopeException(ScopeProblem.CATALOG_TOO_LARGE)
        val groups = mutableMapOf<Int, List<VisibleApp>>()
        val result = linkedMapOf<String, VisibleApp>()
        visible.forEach { app ->
            val peers = groups.getOrPut(app.uid) { checkedMembers(app, members, 1000, ScopeProblem.CATALOG_TOO_LARGE) }
            if (peers.none { it.packageName == app.packageName }) throw AppScopeException(ScopeProblem.INCOMPLETE_UID_GROUP)
            peers.forEach { peer ->
                if (peer.packageName !in result && result.size == 1000) throw AppScopeException(ScopeProblem.CATALOG_TOO_LARGE)
                val prior = result.putIfAbsent(peer.packageName, peer)
                if (prior != null && prior.uid != peer.uid) throw AppScopeException(ScopeProblem.INCOMPLETE_UID_GROUP)
            }
        }
        return result.values.toList()
    }
    fun effective(requested: List<String>, lookup: (String) -> VisibleApp?, members: (Int) -> List<VisibleApp>): List<String> {
        if (requested.isEmpty()) throw AppScopeException(ScopeProblem.EMPTY_SELECTION)
        if (requested.size > 100) throw AppScopeException(ScopeProblem.SELECTION_TOO_LARGE)
        val result = linkedSetOf<String>()
        var packageBytes = 0
        val groups = mutableMapOf<Int, List<VisibleApp>>()
        requested.distinct().forEach { name ->
            val app = lookup(name) ?: throw AppScopeException(ScopeProblem.UNAVAILABLE_APP)
            val peers = groups.getOrPut(app.uid) { checkedMembers(app, members, 100, ScopeProblem.SELECTION_TOO_LARGE) }
            peers.forEach { peer ->
                if (peer.packageName !in result) {
                    if (result.size == 100 || peer.packageName.length > 255) throw AppScopeException(ScopeProblem.SELECTION_TOO_LARGE)
                    val bytes = peer.packageName.toByteArray(Charsets.UTF_8).size
                    if (bytes > 255 || bytes > 4096 - packageBytes) throw AppScopeException(ScopeProblem.SELECTION_TOO_LARGE)
                    result += peer.packageName
                    packageBytes += bytes
                }
            }
        }
        return result.sorted()
    }
    private fun checkedMembers(app: VisibleApp, lookup: (Int) -> List<VisibleApp>, limit: Int, quotaProblem: ScopeProblem): List<VisibleApp> {
        val peers = lookup(app.uid)
        if (peers.size > limit) throw AppScopeException(quotaProblem)
        if (peers.isEmpty() || peers.any { it.uid != app.uid } || peers.none { it.packageName == app.packageName }) {
            throw AppScopeException(ScopeProblem.INCOMPLETE_UID_GROUP)
        }
        return peers.distinctBy { it.packageName }
    }
}

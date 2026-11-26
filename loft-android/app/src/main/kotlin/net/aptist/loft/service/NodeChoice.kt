package net.aptist.loft.service

import net.aptist.loft.core.generated.CoreSnapshot
import net.aptist.loft.core.generated.NodePage
import net.aptist.loft.core.generated.NodeSummary

/** Redacted presentation selection, never an authoritative node catalog. */
data class NodeChoice(val id: String? = null, val summary: NodeSummary? = null) {
    fun select(node: NodeSummary): NodeChoice = NodeChoice(node.id, node)
    fun receive(snapshot: CoreSnapshot): NodeChoice {
        if (snapshot.nodeCount == 0u) return NodeChoice()
        val selected = id ?: snapshot.activeNodeId ?: snapshot.nodes.firstOrNull()?.id
        val metadata = snapshot.nodes.find { it.id == selected } ?: summary.takeIf { it?.id == selected }
        return NodeChoice(selected, metadata)
    }
    fun receive(page: NodePage): NodeChoice = copy(summary = page.nodes.find { it.id == id } ?: summary)
    fun removed(id: String): NodeChoice = if (this.id == id) NodeChoice() else this
}

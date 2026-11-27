package net.aptist.loft

import android.content.res.Configuration
import android.graphics.Rect
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.aptist.loft.ui.AppearancePreferences
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale
import kotlin.math.roundToInt

@RunWith(AndroidJUnit4::class)
class ModuleRailAccessibilityTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Test fun networkTabOpensNodesAndItsMenuOpensImport() {
        val context = instrumentation.targetContext
        val locale = Locale.forLanguageTag(AppearancePreferences(context).locale())
        val localized = context.createConfigurationContext(Configuration(context.resources.configuration).apply { setLocale(locale) })
        val density = localized.resources.displayMetrics.density
        ActivityScenario.launch(MainActivity::class.java).use {
            val home = awaitRailTab("HOME_SELECTED", localized.getString(R.string.module_welcome), selected = true)
            val networkName = localized.getString(R.string.module_vpn)
            val network = awaitRailTab("VPN_UNSELECTED", networkName, selected = false)
            for (node in listOf(home, network)) {
                val bounds = Rect()
                node.getBoundsInScreen(bounds)
                assertTrue("RAIL_TOUCH_WIDTH", bounds.width() >= (48 * density).roundToInt())
                assertTrue("RAIL_TOUCH_HEIGHT", bounds.height() >= (56 * density).roundToInt())
            }
            val overviewName = localized.getString(R.string.overview_title)
            awaitMatch("OVERVIEW_PAGE_TITLE") { node ->
                node.takeIf { it.text?.toString() == overviewName && it.isHeading && !it.isClickable }
            }
            click("VPN_TAB", network)
            awaitRailTab("VPN_SELECTED", networkName, selected = true)
            val nodesName = localized.getString(R.string.node_list)
            val heading = awaitMatch("NODES_PAGE_TITLE") { node ->
                node.takeIf { it.text?.toString() == nodesName && it.isHeading && !it.isClickable }
            }
            val menuName = localized.getString(R.string.open_secondary)
            val menu = awaitAction("VPN_MENU") { it.contentDescription?.toString() == menuName }
            val menuBounds = Rect().also(menu::getBoundsInScreen)
            val headingBounds = Rect().also(heading::getBoundsInScreen)
            assertTrue("VPN_MENU_AT_RIGHT", menuBounds.centerX() > headingBounds.centerX())
            assertTrue("VPN_MENU_TOUCH_WIDTH", menuBounds.width() >= (48 * density).roundToInt())
            assertTrue("VPN_MENU_TOUCH_HEIGHT", menuBounds.height() >= (48 * density).roundToInt())
            click("VPN_MENU", menu)
            val routingName = localized.getString(R.string.routing_title)
            awaitAction("ROUTING_MENU_ITEM") { it.text?.toString() == routingName }
            val importName = localized.getString(R.string.import_link)
            click("IMPORT_MENU_ITEM", awaitAction("IMPORT_MENU_ITEM") { it.text?.toString() == importName })
            awaitMatch("IMPORT_PAGE_TITLE") { node ->
                node.takeIf { it.text?.toString() == importName && it.isHeading && !it.isClickable }
            }
            awaitRailTab("VPN_SELECTED_ON_CHILD", networkName, selected = true)
        }
    }

    private fun awaitRailTab(stage: String, name: String, selected: Boolean): AccessibilityNodeInfo = awaitMatch(stage) { label ->
        if (label.contentDescription?.toString() != name) return@awaitMatch null
        // Compose can expose a merged description as a virtual child of the
        // actionable tab. Read Android's selected property on the tab itself.
        fun isTab(node: AccessibilityNodeInfo) = node.isSelected == selected && (selected || node.isClickable)
        if (isTab(label)) label else label.parent?.takeIf(::isTab)
    }

    private fun awaitAction(stage: String, matches: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo =
        awaitMatch(stage) { label ->
            if (!matches(label)) return@awaitMatch null
            if (label.isClickable) label else label.parent?.takeIf { it.isClickable }
        }

    private fun click(stage: String, node: AccessibilityNodeInfo) {
        assertTrue("RAIL_${stage}_ACTION_AVAILABLE", node.isClickable && node.isEnabled)
        assertTrue("RAIL_${stage}_ACTION_FAILED", node.performAction(AccessibilityNodeInfo.ACTION_CLICK))
    }

    private fun awaitMatch(stage: String, match: (AccessibilityNodeInfo) -> AccessibilityNodeInfo?): AccessibilityNodeInfo {
        val automation = instrumentation.uiAutomation
        val deadline = SystemClock.elapsedRealtime() + 12_000
        do {
            val root = automation.rootInActiveWindow
            if (root != null) find(root, match)?.let { return it }
            SystemClock.sleep(100)
        } while (SystemClock.elapsedRealtime() < deadline)
        error("RAIL_${stage}_ACCESSIBILITY_NODE_MISSING")
    }

    private fun find(node: AccessibilityNodeInfo, match: (AccessibilityNodeInfo) -> AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        match(node)?.let { return it }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            find(child, match)?.let { return it }
        }
        return null
    }
}

package net.aptist.loft

import android.content.res.Configuration
import android.graphics.Rect
import android.os.Bundle
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

/** Run against an isolated app-data instance with the default disabled app PIN. */
@RunWith(AndroidJUnit4::class)
class SecureNotesPresentationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Test
    fun offlineEntryAndArchiveActionsUseTheNativePage() {
        val context = instrumentation.targetContext
        val locale = Locale.forLanguageTag(AppearancePreferences(context).locale())
        val resources = context.createConfigurationContext(Configuration(context.resources.configuration).apply {
            setLocale(locale)
        }).resources
        fun named(id: Int): AccessibilityNodeInfo {
            val label = resources.getString(id)
            return awaitNode(label) { node ->
                (node.contentDescription?.toString() == label || node.text?.toString() == label) && canClick(node)
            }
        }

        ActivityScenario.launch(MainActivity::class.java).use {
            val tab = named(R.string.notes_title)
            press(tab)
            val archive = named(R.string.notes_archive_title)
            val create = named(R.string.notes_create)
            val tagWall = named(R.string.notes_tag_wall)
            val row = listOf(archive, create, tagWall).map { node ->
                Rect().also { bounds -> actionable(node).getBoundsInScreen(bounds) }
            }
            assertTrue("Notes actions use archive, create and tags order", row.zipWithNext().all { (a, b) -> a.centerX() < b.centerX() })
            assertTrue("Create is the largest action", row[1].width() > row[0].width() && row[1].width() > row[2].width())

            press(create)
            val title = awaitNode("note title field") {
                it.isEditable && it.contentDescription?.toString() == resources.getString(R.string.notes_note_title)
            }
            val syntheticNoteTitle = "Device presentation receipt"
            val args = Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, syntheticNoteTitle)
            }
            assertTrue("Compose note field accepts text", title.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args))
            press(named(R.string.notes_save))
            awaitNode("saved note") { it.text?.toString()?.contains(syntheticNoteTitle) == true }
            press(named(R.string.notes_actions))
            press(named(R.string.notes_archive_action))
            press(named(R.string.notes_archive_title))
            awaitNode("archived note") { it.text?.toString()?.contains(syntheticNoteTitle) == true }
            press(named(R.string.notes_actions))
            press(named(R.string.notes_delete))
            awaitNode("delete confirmation") { it.text?.toString() == resources.getString(R.string.notes_delete_title) }
            // Confirm pending deletion by selecting the actionable label in the secure dialog.
            press(named(R.string.notes_delete))
            awaitNode("empty archive") { it.text?.toString() == resources.getString(R.string.notes_no_archive) }
        }
    }

    private fun press(node: AccessibilityNodeInfo) {
        assertTrue("Native notes action is clickable", actionable(node).performAction(AccessibilityNodeInfo.ACTION_CLICK))
    }

    private fun canClick(node: AccessibilityNodeInfo): Boolean =
        generateSequence(node) { it.parent }.any { it.isEnabled && it.isClickable }

    private fun actionable(node: AccessibilityNodeInfo): AccessibilityNodeInfo {
        var candidate: AccessibilityNodeInfo? = node
        while (candidate != null) {
            if (candidate.isEnabled && candidate.isClickable) return candidate
            candidate = candidate.parent
        }
        error("Expected clickable notes action")
    }

    private fun awaitNode(label: String, match: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo {
        val deadline = SystemClock.elapsedRealtime() + 12_000
        do {
            val root = instrumentation.uiAutomation.rootInActiveWindow
            if (root != null) find(root, match)?.let { return it }
            SystemClock.sleep(100)
        } while (SystemClock.elapsedRealtime() < deadline)
        error("Notes accessibility node missing: $label")
    }

    private fun find(node: AccessibilityNodeInfo, match: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        if (match(node)) return node
        for (index in 0 until node.childCount) {
            val child = node.getChild(index) ?: continue
            find(child, match)?.let { return it }
        }
        return null
    }
}

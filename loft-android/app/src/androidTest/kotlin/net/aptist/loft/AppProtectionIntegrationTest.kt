package net.aptist.loft

import android.os.SystemClock
import android.view.WindowManager
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import net.aptist.loft.core.generated.NoteSummary
import net.aptist.loft.core.generated.NotesDraft
import net.aptist.loft.foundation.Page
import net.aptist.loft.service.NotesCommand
import net.aptist.loft.service.NotesResult
import net.aptist.loft.service.ProtectedArea
import net.aptist.loft.ui.LoftViewModel
import net.aptist.loft.ui.ProtectionDisplay
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class AppProtectionIntegrationTest {
    @Test fun pinGatesBothModulesAndReentryWhileOfflineNotesPersist() {
        ActivityScenario.launch(MainActivity::class.java).use { activity ->
            activity.navigate(Page.APP_PROTECTION)
            activity.await("settings protection status") { it.area == ProtectedArea.SETTINGS && it.status != null }
            activity.onActivity { screen ->
                assertTrue(screen.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
                model(screen).protection.configure(
                    model(screen).protection.state.value.status?.enabled?.takeIf { it }?.let { pin() }, pin(), false,
                )
            }
            activity.await("protection enabled") { it.status?.enabled == true && !it.busy }
            var created: NoteSummary? = null
            try {
                activity.navigate(Page.TOTP)
                activity.await("vault locked") { it.area == ProtectedArea.VAULT && it.status?.enabled == true && !it.unlocked }
                activity.onActivity { assertEquals(null, model(it).vault.state.value.page) }
                activity.onActivity { model(it).protection.pin(pin()) }
                activity.await("vault unlocked") { it.area == ProtectedArea.VAULT && it.unlocked }

                activity.navigate(Page.NOTES)
                activity.await("notes locked independently") { it.area == ProtectedArea.NOTES && it.status?.enabled == true && !it.unlocked }
                activity.onActivity {
                    val dispatch = model(it).executeNotes(NotesCommand.ListPage(false, "", null, 0u, null)) { _, _ ->
                        error("Locked notes command returned a data callback")
                    }
                    assertFalse(dispatch)
                    model(it).protection.pin(pin())
                }
                activity.await("notes unlocked") { it.area == ProtectedArea.NOTES && it.unlocked }
                val saved = activity.note(NotesCommand.Save(NotesDraft(null, "Offline journal", "Private **entry**", "🔒", "field|dev", null)))
                    as NotesResult.Saved
                created = saved.value
                val row = activity.note(NotesCommand.ListPage(false, "private", "field", 0u, null)) as NotesResult.Page
                assertEquals(saved.value.id, row.value.entries.single { it.id == saved.value.id }.id)

                activity.moveToState(Lifecycle.State.CREATED)
                activity.moveToState(Lifecycle.State.RESUMED)
                activity.await("notes relocked on activity restart") { it.area == ProtectedArea.NOTES && it.status?.enabled == true && !it.unlocked }
                activity.onActivity { model(it).protection.pin(pin()) }
                activity.await("notes reopened") { it.area == ProtectedArea.NOTES && it.unlocked }
                val detail = activity.note(NotesCommand.Detail(saved.value.id)) as NotesResult.Detail
                assertEquals("Private **entry**", detail.value.body)
                activity.note(NotesCommand.Archive(saved.value.id, true))
                val archived = activity.note(NotesCommand.ListPage(true, "", null, 0u, null)) as NotesResult.Page
                assertTrue(archived.value.entries.any { it.id == saved.value.id })
                activity.note(NotesCommand.Delete(saved.value.id))
                created = null
                val removed = activity.note(NotesCommand.ListPage(true, "", null, 0u, null)) as NotesResult.Page
                assertFalse(removed.value.entries.any { it.id == saved.value.id })
            } finally {
                created?.let { unswept ->
                    activity.onActivity { screen ->
                        val display = model(screen).protection.state.value
                        if (display.area == ProtectedArea.NOTES && display.unlocked) {
                            model(screen).executeNotes(NotesCommand.Delete(unswept.id)) { _, _ -> }
                        }
                    }
                }
                activity.navigate(Page.APP_PROTECTION)
                activity.await("protection settings return") { it.area == ProtectedArea.SETTINGS && it.status?.enabled == true }
                activity.onActivity { model(it).protection.configure(pin(), null, false) }
                activity.await("test PIN removed") { it.status?.enabled == false && !it.busy }
            }
        }
    }

    private fun ActivityScenario<MainActivity>.navigate(page: Page) = onActivity { model(it).navigate(page) }

    private fun ActivityScenario<MainActivity>.await(stage: String, predicate: (ProtectionDisplay) -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 20_000
        do {
            var reached = false
            onActivity { reached = predicate(model(it).protection.state.value) }
            if (reached) return
            SystemClock.sleep(50)
        } while (SystemClock.elapsedRealtime() < deadline)
        error("Protection state missing for $stage")
    }

    private fun ActivityScenario<MainActivity>.note(command: NotesCommand): NotesResult? {
        val receipts = ArrayBlockingQueue<Pair<String, NotesResult?>>(1)
        val dispatchDeadline = SystemClock.elapsedRealtime() + 8_000
        var admitted = false
        do {
            onActivity { screen -> admitted = model(screen).executeNotes(command) { code, result -> receipts.offer(code to result) } }
            if (!admitted) SystemClock.sleep(50)
        } while (!admitted && SystemClock.elapsedRealtime() < dispatchDeadline)
        assertTrue("Notes command admitted", admitted)
        val (code, result) = receipts.poll(20, TimeUnit.SECONDS) ?: error("Notes receipt missing")
        assertEquals("ok", code)
        return result
    }

    private fun model(activity: MainActivity): LoftViewModel = ViewModelProvider(activity)[LoftViewModel::class.java]

    // Synthetic test PIN used only in the API test's isolated app data.
    private fun pin(): ByteArray = byteArrayOf(49, 57, 50, 56, 51, 55)
}

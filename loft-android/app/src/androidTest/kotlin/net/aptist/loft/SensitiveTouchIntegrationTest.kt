package net.aptist.loft

import android.content.Context
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.WindowManager
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.aptist.loft.foundation.Page
import net.aptist.loft.ui.LoftViewModel
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises the actual Activity/decor dispatcher with Android MotionEvents.
 * Injected flags prove dispatch behavior; real overlay-window acceptance is separate.
 */
@RunWith(AndroidJUnit4::class)
class SensitiveTouchIntegrationTest {
    private class ClickTarget(context: Context) : Button(context) {
        var clicks = 0
        val received = mutableListOf<Pair<Int, Int>>()
        init { setOnClickListener { clicks++ } }
        override fun onTouchEvent(event: MotionEvent): Boolean {
            received += event.actionMasked to event.flags
            return super.onTouchEvent(event)
        }
    }

    @Test fun sensitivePagesRejectObscuredDownFollowedByCleanUp() = withTarget { scenario, target ->
        scenario.onActivity { activity ->
            for (page in listOf(Page.IMPORT_NODE, Page.ACCOUNT)) {
                activity.setSensitivePage(page)
                for (flags in listOf(MotionEvent.FLAG_WINDOW_IS_OBSCURED, MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) {
                    val started = SystemClock.uptimeMillis()
                    dispatch(activity, target, started, MotionEvent.ACTION_DOWN, flags)
                    dispatch(activity, target, started, MotionEvent.ACTION_UP, 0)
                }
            }
        }
        idle()
        scenario.onActivity { assertEquals(0, target.clicks); assertTrue(target.received.isEmpty()) }
    }

    @Test fun midGestureObscurationReachesThePressedControlAsCleanCancel() = withTarget { scenario, target ->
        scenario.onActivity { it.setSensitivePage(Page.IMPORT_NODE) }
        for (flags in listOf(MotionEvent.FLAG_WINDOW_IS_OBSCURED, MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED)) {
            scenario.onActivity { activity ->
                target.received.clear()
                val started = SystemClock.uptimeMillis()
                dispatch(activity, target, started, MotionEvent.ACTION_DOWN, 0)
                dispatch(activity, target, started, MotionEvent.ACTION_MOVE, flags)
                dispatch(activity, target, started, MotionEvent.ACTION_UP, 0)
            }
            idle()
            scenario.onActivity {
                assertEquals(listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_CANCEL), target.received.map { it.first })
                assertEquals(0, target.received.last().second and OBSCURED_FLAGS)
                assertEquals(0, target.clicks)
            }
        }
        scenario.onActivity { activity ->
            val fresh = SystemClock.uptimeMillis()
            dispatch(activity, target, fresh, MotionEvent.ACTION_DOWN, 0)
            dispatch(activity, target, fresh, MotionEvent.ACTION_UP, 0)
        }
        idle()
        scenario.onActivity { assertEquals(1, target.clicks) }
    }

    @Test fun normalInputAndAccessibilityActionsRemainUsable() = withTarget { scenario, target ->
        scenario.onActivity { activity ->
            activity.setSensitivePage(Page.WELCOME)
            val normal = SystemClock.uptimeMillis()
            dispatch(activity, target, normal, MotionEvent.ACTION_DOWN, OBSCURED_FLAGS)
            dispatch(activity, target, normal, MotionEvent.ACTION_UP, OBSCURED_FLAGS)
            assertFalse(activity.window.decorView.filterTouchesWhenObscured)
        }
        idle()
        scenario.onActivity { activity ->
            assertEquals(1, target.clicks)
            activity.setSensitivePage(Page.ACCOUNT)
            val sensitive = SystemClock.uptimeMillis()
            dispatch(activity, target, sensitive, MotionEvent.ACTION_DOWN, 0)
            dispatch(activity, target, sensitive, MotionEvent.ACTION_UP, 0)
        }
        idle()
        scenario.onActivity {
            assertEquals(2, target.clicks)
            assertTrue(target.performAccessibilityAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_CLICK.id, null))
        }
        idle()
        scenario.onActivity { assertEquals(3, target.clicks) }
    }

    @Test fun sensitiveScopeSurvivesRecreationAndBackgroundThenClearsOnPageLeave() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                ViewModelProvider(activity)[LoftViewModel::class.java].navigate(Page.IMPORT_NODE)
                activity.setSensitivePage(Page.IMPORT_NODE)
                assertTrue(secure(activity))
                assertTrue(activity.window.decorView.filterTouchesWhenObscured)
            }
            scenario.moveToState(Lifecycle.State.CREATED)
            scenario.onActivity { activity ->
                assertTrue(secure(activity))
                assertFalse(activity.window.decorView.filterTouchesWhenObscured)
            }
            scenario.moveToState(Lifecycle.State.RESUMED)
            scenario.recreate()
            scenario.onActivity { activity ->
                assertTrue(secure(activity))
                assertTrue(activity.window.decorView.filterTouchesWhenObscured)
                ViewModelProvider(activity)[LoftViewModel::class.java].navigate(Page.WELCOME)
                activity.setSensitivePage(Page.WELCOME)
                assertFalse(secure(activity))
                assertFalse(activity.window.decorView.filterTouchesWhenObscured)
            }
        }
    }

    private fun withTarget(check: (ActivityScenario<MainActivity>, ClickTarget) -> Unit) {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            lateinit var target: ClickTarget
            scenario.onActivity { activity -> target = ClickTarget(activity); activity.setContentView(target) }
            idle()
            check(scenario, target)
        }
    }
    private fun idle() = InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    private fun dispatch(activity: MainActivity, target: ClickTarget, downTime: Long, action: Int, flags: Int) {
        assertTrue(target.width > 0 && target.height > 0)
        val location = IntArray(2).also(target::getLocationInWindow)
        val properties = arrayOf(MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER })
        val coordinates = arrayOf(MotionEvent.PointerCoords().apply {
            x = location[0] + target.width / 2f; y = location[1] + target.height / 2f
            pressure = 1f; size = 1f
        })
        val event = MotionEvent.obtain(downTime, SystemClock.uptimeMillis(), action, 1, properties, coordinates,
            0, 0, 1f, 1f, 0, 0, InputDevice.SOURCE_TOUCHSCREEN, flags)
        try { activity.dispatchTouchEvent(event) } finally { event.recycle() }
    }
    private fun secure(activity: MainActivity) = activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
    private companion object {
        const val OBSCURED_FLAGS = MotionEvent.FLAG_WINDOW_IS_OBSCURED or MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED
    }
}

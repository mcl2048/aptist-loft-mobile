package net.aptist.loft

import android.os.Bundle
import android.os.Build
import android.Manifest
import android.content.pm.PackageManager
import android.content.Intent
import android.net.VpnService
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.window.layout.FoldingFeature
import androidx.window.layout.WindowInfoTracker
import kotlinx.coroutines.launch
import net.aptist.loft.foundation.ObscuredTouchGate
import net.aptist.loft.foundation.Page
import net.aptist.loft.foundation.TouchDispatch
import net.aptist.loft.ui.*
import net.aptist.loft.service.LoftNotificationChannels

class MainActivity : AppCompatActivity() {
    private lateinit var model: LoftViewModel
    private val touchGate = ObscuredTouchGate()
    private var sensitivePage = false
    private var windowActive = false
    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        model.completeVpnPermission(result.resultCode == RESULT_OK)
    }
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        model.refreshNotificationAccess(); launchVpnPermission()
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        val preferences = AppearancePreferences(this)
        applyTheme(preferences.theme())
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(preferences.locale()))
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        model = ViewModelProvider(this)[LoftViewModel::class.java]
        LoftNotificationChannels.ensure(this)
        if (intent?.action == LoftNotificationChannels.OPEN_MAIL) model.navigate(Page.MAIL)
        setSensitivePage(model.ui.value.presentation.navigation.page)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                WindowInfoTracker.getOrCreate(this@MainActivity).windowLayoutInfo(this@MainActivity).collect { info ->
                    model.setFolds(info.displayFeatures.filterIsInstance<FoldingFeature>().map { fold ->
                        PhysicalFold(fold.bounds.left, fold.bounds.top, fold.bounds.right, fold.bounds.bottom,
                            fold.orientation == FoldingFeature.Orientation.VERTICAL, fold.isSeparating,
                            fold.occlusionType == FoldingFeature.OcclusionType.FULL, fold.state == FoldingFeature.State.HALF_OPENED)
                    })
                }
            }
        }
        setContent {
            LoftApp(model, onExit = ::finish, onTheme = { value -> model.setTheme(value); applyTheme(value) },
                onLocale = { value -> model.setLocale(value); AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(value)) }, onConnect = ::requestConnection)
        }
    }
    override fun onStart() {
        super.onStart()
        windowActive = true
        setSensitivePage(model.ui.value.presentation.navigation.page)
        applySensitiveWindow()
        model.setVisible(true)
        model.refreshNotificationAccess()
    }
    override fun onStop() {
        model.setVisible(false)
        windowActive = false
        applySensitiveWindow()
        super.onStop()
    }
    override fun onDestroy() {
        windowActive = false
        sensitivePage = false
        applySensitiveWindow()
        touchGate.reset()
        super.onDestroy()
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent); setIntent(intent)
        if (intent.action == LoftNotificationChannels.OPEN_MAIL) model.navigate(Page.MAIL)
    }

    fun setSensitivePage(page: Page) {
        val sensitive = page == Page.IMPORT_NODE || page == Page.ACCOUNT
        if (sensitivePage == sensitive) return
        sensitivePage = sensitive
        applySensitiveWindow()
    }
    private fun applySensitiveWindow() {
        val protectInput = sensitivePage && windowActive
        touchGate.setSensitive(protectInput)
        window.decorView.filterTouchesWhenObscured = protectInput
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(protectInput)
        // Keep sensitive background/recents protected until page leave or destroy.
        if (sensitivePage) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
    override fun dispatchTouchEvent(event: MotionEvent): Boolean = when (touchGate.decide(event.actionMasked, event.flags)) {
        TouchDispatch.PASS -> super.dispatchTouchEvent(event)
        TouchDispatch.CONSUME -> true
        TouchDispatch.CANCEL_AND_CONSUME -> {
            val properties = Array(event.pointerCount) { MotionEvent.PointerProperties().also { pointer -> event.getPointerProperties(it, pointer) } }
            val coordinates = Array(event.pointerCount) { MotionEvent.PointerCoords().also { pointer -> event.getPointerCoords(it, pointer) } }
            // A cloned obscured event can be filtered by decor before Compose
            // receives CANCEL. Use public APIs to clear obscuration flags.
            val cancel = MotionEvent.obtain(event.downTime, event.eventTime, MotionEvent.ACTION_CANCEL, event.pointerCount,
                properties, coordinates, event.metaState, event.buttonState, event.xPrecision, event.yPrecision,
                event.deviceId, event.edgeFlags, event.source, 0)
            try { super.dispatchTouchEvent(cancel) } finally { cancel.recycle() }
            true
        }
    }
    private fun requestConnection() {
        if (!model.prepareVpnPermission()) return
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else launchVpnPermission()
    }
    private fun launchVpnPermission() {
        if (!model.ui.value.vpnPermissionPending) return
        val intent = VpnService.prepare(this)
        if (intent == null) model.completeVpnPermission(true) else vpnPermission.launch(intent)
    }
    private fun applyTheme(choice: ThemeChoice) {
        AppCompatDelegate.setDefaultNightMode(when (choice) {
            ThemeChoice.SYSTEM -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
            ThemeChoice.LIGHT -> AppCompatDelegate.MODE_NIGHT_NO
            ThemeChoice.DARK -> AppCompatDelegate.MODE_NIGHT_YES
        })
    }
}

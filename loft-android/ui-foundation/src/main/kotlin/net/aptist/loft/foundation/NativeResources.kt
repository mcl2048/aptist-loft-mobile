package net.aptist.loft.foundation

/** Infrastructure ownership only; Rust remains the business-state authority. */
class NativeResources<C : AutoCloseable, G : AutoCloseable>(
    private val coreFactory: () -> C,
    private val goFactory: () -> G,
) : AutoCloseable {
    private var core: C? = null
    private var go: G? = null
    private var uiLeases = 0
    private var vpnLeases = 0
    @Synchronized fun retainUi(): C {
        val resource = core ?: coreFactory().also { core = it }
        uiLeases = Math.addExact(uiLeases, 1)
        return resource
    }
    @Synchronized fun retainVpn(): C {
        val resource = core ?: coreFactory().also { core = it }
        vpnLeases = Math.addExact(vpnLeases, 1)
        return resource
    }
    @Synchronized fun currentCore(): C = checkNotNull(core)
    @Synchronized fun explicitGo(): G {
        checkNotNull(core)
        return go ?: goFactory().also { go = it }
    }
    @Synchronized fun releaseUi() {
        if (uiLeases == 0) return
        uiLeases--
        closeIfIdle()
    }
    @Synchronized fun releaseGo() {
        go?.close()
        go = null
    }
    @Synchronized fun releaseVpn(confirmedReleased: Boolean): Boolean {
        if (!confirmedReleased) return false
        if (vpnLeases == 0) return true
        if (vpnLeases == 1) releaseGo()
        vpnLeases--
        closeIfIdle()
        return true
    }
    private fun closeIfIdle() {
        if (uiLeases != 0 || vpnLeases != 0) return
        releaseGo()
        core?.close()
        core = null
    }
    @Synchronized override fun close() {
        releaseGo()
        core?.close()
        core = null; uiLeases = 0; vpnLeases = 0
    }
}

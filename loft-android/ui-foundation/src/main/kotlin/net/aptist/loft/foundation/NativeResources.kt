package net.aptist.loft.foundation

/** Infrastructure ownership only; Rust remains the business-state authority. */
class NativeResources<C : AutoCloseable, G : AutoCloseable>(
    private val coreFactory: () -> C,
    private val goFactory: () -> G,
) : AutoCloseable {
    private val openLock = Any()
    private var core: C? = null
    private var go: G? = null
    private var uiLeases = 0
    private var vpnLeases = 0
    fun retainUi(): C = retainCore(vpnLease = false)
    fun retainVpn(): C = retainCore(vpnLease = true)
    fun retainExistingUi(): C? = retainExisting(vpnLease = false)

    private fun retainCore(vpnLease: Boolean): C = retainExisting(vpnLease) ?: synchronized(openLock) {
        retainExisting(vpnLease) ?: coreFactory().also { resource ->
            synchronized(this) {
                core = resource
                addLease(vpnLease)
            }
        }
    }

    @Synchronized private fun retainExisting(vpnLease: Boolean): C? = core?.also { addLease(vpnLease) }

    private fun addLease(vpnLease: Boolean) {
        if (vpnLease) vpnLeases = Math.addExact(vpnLeases, 1)
        else uiLeases = Math.addExact(uiLeases, 1)
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
    @Synchronized fun releaseSoleUiLease(): Boolean {
        if (uiLeases != 1 || vpnLeases != 0) return false
        releaseUi()
        return true
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
    override fun close() = synchronized(openLock) {
        synchronized(this) {
            releaseGo()
            core?.close()
            core = null; uiLeases = 0; vpnLeases = 0
        }
    }
}

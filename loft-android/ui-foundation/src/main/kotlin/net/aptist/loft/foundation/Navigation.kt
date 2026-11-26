package net.aptist.loft.foundation

enum class ModuleId(val stableId: String) {
    WELCOME("welcome"), VPN("vpn"), SHIELD("shield"), MAIL("mail"), TOTP("totp"), AUDIT("audit"), SETTING("setting"), ACCOUNT("account")
}

enum class Page(val module: ModuleId, val stableId: String) {
    WELCOME(ModuleId.WELCOME, "home"),
    VPN_HOME(ModuleId.VPN, "home"), NODES(ModuleId.VPN, "nodes"), NODE_DETAILS(ModuleId.VPN, "node"),
    IMPORT_NODE(ModuleId.VPN, "import"), ROUTING(ModuleId.VPN, "routing"), DIAGNOSTICS(ModuleId.VPN, "diagnostics"),
    SHIELD(ModuleId.SHIELD, "home"), MAIL(ModuleId.MAIL, "home"), TOTP(ModuleId.TOTP, "home"), AUDIT(ModuleId.AUDIT, "home"),
    SETTINGS(ModuleId.SETTING, "home"), ACCOUNT(ModuleId.ACCOUNT, "home")
}

data class NavigationState(
    val page: Page = Page.WELCOME,
    val menuOpen: Boolean = false,
    val pendingPage: Page? = null,
) {
    val module: ModuleId get() = page.module
    fun navigate(target: Page, dirty: Boolean): NavigationState = when {
        target == page -> copy(menuOpen = false, pendingPage = null)
        dirty -> copy(menuOpen = false, pendingPage = target)
        else -> copy(page = target, menuOpen = false, pendingPage = null)
    }
    fun back(dirty: Boolean): NavigationState = when {
        menuOpen -> copy(menuOpen = false)
        page.module == ModuleId.VPN && page != Page.VPN_HOME -> navigate(Page.VPN_HOME, dirty)
        page != Page.WELCOME -> navigate(Page.WELCOME, dirty)
        else -> this
    }
    fun discardAndNavigate(): NavigationState = pendingPage?.let { copy(page = it, menuOpen = false, pendingPage = null) } ?: this
    fun keepEditing(): NavigationState = copy(pendingPage = null)
    fun withAvailableModules(available: Set<ModuleId>): NavigationState =
        if (module in available) this else NavigationState()
}

enum class EntryPolicy { LOCAL_ENTRY, DEPENDENCY_INFORMATION, SERVER_CAPABILITY }
data class ModuleRegistration(val id: ModuleId, val entry: Page, val children: List<Page>,
    val titleKey: String, val shortTitleKey: String, val iconKey: String, val policy: EntryPolicy)

object ModuleCatalog {
    val schemaVersion = 1
    val registrations = listOf(
        ModuleRegistration(ModuleId.WELCOME, Page.WELCOME, emptyList(), "module_welcome", "rail_welcome", "home", EntryPolicy.LOCAL_ENTRY),
        ModuleRegistration(ModuleId.VPN, Page.VPN_HOME, listOf(Page.NODES, Page.NODE_DETAILS, Page.IMPORT_NODE, Page.ROUTING, Page.DIAGNOSTICS), "module_vpn", "rail_vpn", "network", EntryPolicy.LOCAL_ENTRY),
        ModuleRegistration(ModuleId.SHIELD, Page.SHIELD, emptyList(), "module_shield", "rail_shield", "shield", EntryPolicy.DEPENDENCY_INFORMATION),
        ModuleRegistration(ModuleId.MAIL, Page.MAIL, emptyList(), "module_mail", "rail_mail", "mail", EntryPolicy.SERVER_CAPABILITY),
        ModuleRegistration(ModuleId.TOTP, Page.TOTP, emptyList(), "vault_title", "vault_title", "vault", EntryPolicy.LOCAL_ENTRY),
        ModuleRegistration(ModuleId.AUDIT, Page.AUDIT, emptyList(), "module_audit", "rail_audit", "log", EntryPolicy.LOCAL_ENTRY),
        ModuleRegistration(ModuleId.SETTING, Page.SETTINGS, emptyList(), "module_setting", "rail_setting", "settings", EntryPolicy.LOCAL_ENTRY),
        ModuleRegistration(ModuleId.ACCOUNT, Page.ACCOUNT, listOf(Page.MAIL), "module_account", "module_account", "account", EntryPolicy.LOCAL_ENTRY),
    )
    fun rail(mailAvailable: Boolean, savedOrder: List<String> = emptyList()): List<ModuleId> {
        val available = registrations.map { it.id }.filter { it != ModuleId.ACCOUNT && (it != ModuleId.MAIL || mailAvailable) }
        val requested = savedOrder.mapNotNull { id -> available.find { it.stableId == id } }.distinct()
        return requested + available.filterNot { it in requested }
    }
    fun resolve(moduleId: String, pageId: String): Page? =
        registrations.find { it.id.stableId == moduleId }?.let { registration ->
            (listOf(registration.entry) + registration.children).find { it.stableId == pageId && it.module.stableId == moduleId }
        }
    fun entry(module: ModuleId): Page = registrations.first { it.id == module }.entry
    fun children(module: ModuleId): List<Page> = registrations.first { it.id == module }.children
}

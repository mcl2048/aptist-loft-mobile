package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class NavigationTest {
    @Test fun vpnEntryOpensDirectoryAndPreservesExistingStableRoutes() {
        assertEquals(Page.NODES, ModuleCatalog.entry(ModuleId.VPN))
        assertEquals(Page.VPN_HOME, ModuleCatalog.resolve("vpn", "home"))
        assertEquals(Page.NODES, ModuleCatalog.resolve("vpn", "nodes"))
    }

    @Test fun backReturnsFromNetworkChildrenToDirectoryThenOverview() {
        val child = NavigationState(page = Page.IMPORT_NODE)
        val pending = child.back(dirty = true)
        assertEquals(Page.IMPORT_NODE, pending.page)
        assertEquals(Page.NODES, pending.pendingPage)
        val directory = pending.discardAndNavigate()
        assertEquals(Page.NODES, directory.page)
        assertEquals(Page.WELCOME, directory.back(dirty = false).page)
        assertEquals(Page.NODES, NavigationState(page = Page.VPN_HOME).back(dirty = false).page)
        assertEquals(Page.NODES, NavigationState(page = Page.NODE_DETAILS).back(dirty = false).page)
    }

    // Catches secondary navigation losing its persistent parent-module selection.
    @Test fun routingPageKeepsNetworkSelected() {
        val state = NavigationState().navigate(Page.ROUTING, dirty = false)
        assertEquals(ModuleId.VPN, state.module)
        assertEquals(Page.ROUTING, state.page)
    }

    // Catches a menu close incorrectly popping the page or discarding a draft.
    @Test fun backClosesSecondaryMenuBeforeLeavingDraft() {
        val state = NavigationState(page = Page.ROUTING, menuOpen = true).back(dirty = true)
        assertEquals(Page.ROUTING, state.page)
        assertFalse(state.menuOpen)
        assertNull(state.pendingPage)
    }

    // Catches rail navigation silently losing a user's in-memory edits.
    @Test fun editedDraftRequiresExplicitDiscardBeforeSwitchingModules() {
        val proposed = NavigationState(page = Page.IMPORT_NODE).navigate(Page.SHIELD, dirty = true)
        assertEquals(Page.IMPORT_NODE, proposed.page)
        assertEquals(Page.SHIELD, proposed.pendingPage)
        assertEquals(Page.SHIELD, proposed.discardAndNavigate().page)
    }

    @Test fun cancelDiscardKeepsTheOriginalPage() {
        val proposed = NavigationState(page = Page.ROUTING).navigate(Page.WELCOME, dirty = true)
        assertEquals(Page.WELCOME, proposed.pendingPage)
        assertEquals(Page.ROUTING, proposed.keepEditing().page)
        assertNull(proposed.keepEditing().pendingPage)
    }

    // Catches a removed capability leaving an invalid route active.
    @Test fun unavailableModuleFallsBackToWelcome() {
        val state = NavigationState(page = Page.MAIL).withAvailableModules(setOf(ModuleId.WELCOME, ModuleId.VPN))
        assertEquals(Page.WELCOME, state.page)
    }

    // Catches index-based preferences reordering the wrong compiled module.
    @Test fun moduleOrderUsesStableIdsAndIgnoresUnknownDuplicates() {
        assertEquals(
            listOf(ModuleId.SHIELD, ModuleId.VPN, ModuleId.WELCOME, ModuleId.TOTP, ModuleId.AUDIT, ModuleId.SETTING),
            ModuleCatalog.rail(mailAvailable = false, savedOrder = listOf("shield", "vpn", "shield", "remote")),
        )
    }

    // Catches displaying a private inbox entry before its server capability exists.
    @Test fun mailRailRequiresAnActualCapability() {
        assertFalse(ModuleCatalog.rail(mailAvailable = false).contains(ModuleId.MAIL))
        assertTrue(ModuleCatalog.rail(mailAvailable = true).contains(ModuleId.MAIL))
        assertNull(ModuleCatalog.resolve("vpn", "remote-code"))
        assertEquals(Page.NODES, ModuleCatalog.resolve("vpn", "nodes"))
    }

    @Test fun authenticatorHasAStableOfflineEntry() {
        assertEquals(Page.TOTP, ModuleCatalog.resolve("totp", "home"))
        assertTrue(ModuleCatalog.rail(mailAvailable = false).contains(ModuleId.TOTP))
        assertEquals(EntryPolicy.LOCAL_ENTRY, ModuleCatalog.registrations.single { it.id == ModuleId.TOTP }.policy)
    }
}

package net.aptist.loft.service

import net.aptist.loft.R
import net.aptist.loft.foundation.CoreCommand
import net.aptist.loft.core.generated.CoreException

enum class ReceiptCode(val text: Int, val successful: Boolean = false) {
    NODE_IMPORTED(R.string.ok_node_imported, true), NODE_REMOVED(R.string.ok_node_removed, true),
    SERVER_STAGED(R.string.ok_server_staged, true), SERVER_RESET(R.string.ok_server_reset, true),
    ROUTING_STAGED(R.string.ok_routing_staged, true), CONTROL_STOPPED(R.string.ok_control_stopped, true),
    VPN_STARTING(R.string.ok_vpn_starting, true), TUN_CLOSED_CORE_UNAVAILABLE(R.string.ok_tun_closed_core_unavailable),
    NODE_PAGE_READY(R.string.node_page_loaded, true), INVALID_NODE_PAGE(R.string.err_invalid_node_page),
    INPUT_TOO_LARGE(R.string.err_input_too_large), INVALID_URI(R.string.err_invalid_uri),
    UNSUPPORTED_PROTOCOL(R.string.err_unsupported_protocol), MISSING_FIELD(R.string.err_missing_field),
    DUPLICATE_PARAMETER(R.string.err_duplicate_parameter), UNKNOWN_PARAMETER(R.string.err_unknown_parameter),
    INVALID_ENDPOINT(R.string.err_invalid_endpoint), INVALID_CREDENTIAL(R.string.err_invalid_credential),
    INVALID_CERTIFICATE(R.string.err_invalid_certificate), INVALID_OPTION(R.string.err_invalid_option),
    DUPLICATE_NODE(R.string.err_duplicate_node), NODE_CAPACITY_REACHED(R.string.err_node_capacity_reached),
    NODE_NOT_FOUND(R.string.err_node_not_found), INVALID_SERVER_ADDRESS(R.string.err_invalid_server_address),
    EMPTY_ROUTING_SELECTION(R.string.err_empty_routing_selection), INVALID_PACKAGE_NAME(R.string.err_invalid_package_name),
    ROUTING_SELECTION_TOO_LARGE(R.string.err_routing_selection_too_large), GENERATION_EXHAUSTED(R.string.err_generation_exhausted),
    DATA_PLANE_UNAVAILABLE(R.string.err_data_plane_unavailable), STATE_UNAVAILABLE(R.string.err_state_unavailable),
    CONTROL_TOO_LARGE(R.string.err_control_too_large), INVALID_COMMAND(R.string.err_invalid_command),
    NATIVE_UNAVAILABLE(R.string.err_native_unavailable), RESOURCE_BUSY(R.string.err_resource_busy),
    VPN_PERMISSION_DENIED(R.string.err_vpn_permission), VPN_START_FAILED(R.string.err_vpn_start_failed),
    VPN_BLOCKED(R.string.err_vpn_blocked), VPN_NETWORK_UNAVAILABLE(R.string.err_vpn_network_unavailable),
    STALE_GENERATION(R.string.err_stale_generation), CONNECTION_BUSY(R.string.err_connection_busy),
    NODE_IN_USE(R.string.err_node_in_use), TICKET_EXPIRED(R.string.err_ticket_expired),
    INVALID_ENGINE_RECEIPT(R.string.err_invalid_engine_receipt), INVALID_ROUTING_RECEIPT(R.string.err_invalid_routing_receipt),
    ENGINE_STOP_INCOMPLETE(R.string.err_engine_stop_incomplete), PUBLICATION_EXHAUSTED(R.string.err_publication_exhausted),
    APP_UNAVAILABLE(R.string.err_app_unavailable), APP_QUERY_FAILED(R.string.err_app_query), APP_CATALOG_LIMIT(R.string.err_app_catalog_limit),
    CLIPBOARD_EMPTY(R.string.err_clipboard_empty), NETWORK_PRIVACY_STAGED(R.string.ok_network_privacy_staged, true),
    INVALID_NETWORK_PRIVACY_POLICY(R.string.err_network_privacy_policy), INVALID_NETWORK_PRIVACY_RECEIPT(R.string.err_network_privacy_receipt),
    UNSUPPORTED_NETWORK_PRIVACY_POLICY(R.string.err_network_privacy_unsupported), UNKNOWN(R.string.err_unknown);

    companion object {
        fun parse(code: String): ReceiptCode = entries.find { it.name == code } ?: UNKNOWN
        // Only typed, flat error codes cross IPC. Messages/stack traces do not.
        fun nativeFailure(failure: Exception): ReceiptCode {
            if (failure !is CoreException) return STATE_UNAVAILABLE
            return when (failure) {
                is CoreException.InputTooLarge -> INPUT_TOO_LARGE
                is CoreException.InvalidUri -> INVALID_URI
                is CoreException.UnsupportedProtocol -> UNSUPPORTED_PROTOCOL
                is CoreException.MissingField -> MISSING_FIELD
                is CoreException.DuplicateParameter -> DUPLICATE_PARAMETER
                is CoreException.UnknownParameter -> UNKNOWN_PARAMETER
                is CoreException.InvalidEndpoint -> INVALID_ENDPOINT
                is CoreException.InvalidCredential -> INVALID_CREDENTIAL
                is CoreException.InvalidCertificate -> INVALID_CERTIFICATE
                is CoreException.InvalidOption -> INVALID_OPTION
                is CoreException.DuplicateNode -> DUPLICATE_NODE
                is CoreException.NodeCapacityReached -> NODE_CAPACITY_REACHED
                is CoreException.NodeNotFound -> NODE_NOT_FOUND
                is CoreException.InvalidServerAddress -> INVALID_SERVER_ADDRESS
                is CoreException.EmptyRoutingSelection -> EMPTY_ROUTING_SELECTION
                is CoreException.InvalidPackageName -> INVALID_PACKAGE_NAME
                is CoreException.RoutingSelectionTooLarge -> ROUTING_SELECTION_TOO_LARGE
                is CoreException.GenerationExhausted -> GENERATION_EXHAUSTED
                is CoreException.DataPlaneUnavailable -> DATA_PLANE_UNAVAILABLE
                is CoreException.StateUnavailable -> STATE_UNAVAILABLE
                is CoreException.StaleGeneration -> STALE_GENERATION
                is CoreException.ConnectionBusy -> CONNECTION_BUSY
                is CoreException.NodeInUse -> NODE_IN_USE
                is CoreException.TicketExpired -> TICKET_EXPIRED
                is CoreException.InvalidEngineReceipt -> INVALID_ENGINE_RECEIPT
                is CoreException.InvalidRoutingReceipt -> INVALID_ROUTING_RECEIPT
                is CoreException.EngineStopIncomplete -> ENGINE_STOP_INCOMPLETE
                is CoreException.InvalidNodePage -> INVALID_NODE_PAGE
                is CoreException.InvalidNetworkPrivacyPolicy -> INVALID_NETWORK_PRIVACY_POLICY
                is CoreException.InvalidNetworkPrivacyReceipt -> INVALID_NETWORK_PRIVACY_RECEIPT
                is CoreException.UnsupportedNetworkPrivacyPolicy -> UNSUPPORTED_NETWORK_PRIVACY_POLICY
            }
        }
    }
}

enum class OperationKind {
    IMPORT, REMOVE, SERVER, RESET_SERVER, ROUTING, CONNECT, STOP, NETWORK_PRIVACY;
    companion object {
        fun of(command: CoreCommand): OperationKind = when (command) {
            is CoreCommand.ImportNode -> IMPORT
            is CoreCommand.RemoveNode -> REMOVE
            is CoreCommand.StageServer -> SERVER
            CoreCommand.ResetServer -> RESET_SERVER
            is CoreCommand.SetRouting -> ROUTING
            is CoreCommand.Connect -> CONNECT
            CoreCommand.Stop -> STOP
            is CoreCommand.SetNetworkPrivacyPolicy -> NETWORK_PRIVACY
        }
    }
}

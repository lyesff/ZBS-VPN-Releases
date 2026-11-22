package dev.autowarp

/** One explicit, non-sensitive schema for storage and shareable export. */
internal object VpnJournalPolicy {
    const val LIMIT=256
    val codes=setOf("start","network_wifi","network_cellular","network_other",
            "network_missing","core_start","core_ready","probe_start","probe_ok",
            "probe_fail","route_switch","route_online","route_failed","recover",
            "stopped","core_failed","scan_start","scan_done",
            "awg_probe_start","awg_probe_ok","awg_probe_fail","awg_doh_start","awg_doh_ready","awg_doh_failed",
            "awg_vpn_start","awg_nested_prepare","awg_nested_prepared","awg_nested_prepare_failed","awg_nested_reg_post","awg_nested_reg_activate","awg_nested_start","awg_nested_outer_country","awg_nested_outer_meta","awg_nested_inner_meta","awg_nested_meta_node","awg_nested_inner_country","awg_nested_done","awg_vpn_scope_app","awg_vpn_scope_all","awg_vpn_mask_retry","awg_vpn_mask_original","awg_vpn_mask_router_i1","awg_vpn_mask_quic","awg_vpn_mask_dns","awg_vpn_mask_stun","awg_vpn_app_only_verified","awg_vpn_tun","awg_vpn_udp_reused","awg_vpn_session_reused","awg_vpn_post_tun_start","awg_vpn_post_tun","awg_vpn_post_tun_udp","awg_vpn_transport_state","awg_vpn_handshake","awg_vpn_verified","awg_vpn_exit_country","awg_node_scan_start","awg_node_scan_done","awg_vpn_trace_node","awg_picker_start","awg_picker_candidate","awg_picker_exhausted","awg_picker_saved","awg_vpn_region_rejected","awg_vpn_check_start","awg_vpn_check_ok","awg_vpn_check_failed","awg_vpn_failed","awg_vpn_flow","awg_vpn_tcp_trace","awg_vpn_tcp_bound","awg_vpn_tcp_default","awg_vpn_verify_attempt","awg_vpn_tcp_connected","awg_vpn_tls_ready","awg_vpn_tcp_data","awg_vpn_udp_flow","awg_vpn_udp_bound","awg_vpn_udp_bind_failed","awg_vpn_go_before","awg_vpn_go_after","awg_vpn_transport_preflight_start","awg_vpn_transport_preflight") + setOf(
        "awg_vpn_watchdog_failed",
        "awg_vpn_network_wait",
        "awg_vpn_network_changed",
        "awg_vpn_wifi_preferred",
        "awg_vpn_wifi_probe_failed",
        "awg_vpn_network_monitor_unavailable",
        "awg_screen_off",
        "awg_screen_on",
        "awg_idle_enter",
        "awg_idle_exit",
        "awg_battery_exempt",
        "awg_battery_optimized",
        "awg_notifications_enabled",
        "awg_notifications_disabled",
        "awg_background_monitor_started",
        "awg_background_monitor_unavailable",
        "awg_vpn_network_blocked",
        "awg_vpn_network_unblocked",
        "awg_vpn_network_suspended",
        "awg_vpn_network_resumed",
        "awg_vpn_recovery_start",
        "awg_vpn_user_stop",
        "awg_vpn_permission_revoked",
        "awg_vpn_service_destroyed")
    private val kinds=setOf("WARP","VLESS","other","")
    fun accepts(code:String,kind:String)=code in codes && kind in kinds
    fun safeError(error:String)=error.takeIf { it.matches(Regex("probe_(?:timeout|cancelled|dns|tls_certificate|tls_handshake|network_unreachable|host_unreachable|connection_refused|connection_reset|connection_closed|transport|trace_body|trace_ip|warp_not_confirmed|http_[0-9]{3}|unknown)|awg_nested_(?:geo_disagree|prepared|prepare_failed|reg_wait|reg_timeout|reg_dns|reg_tls|reg_network|reg_format|reg_http_[1-5][0-9]{2}|launch_blocked|permission_denied|running|verified|region_ru|region_unknown|outer_node|outer_failed|inner_failed|same_key|invalid|protect_failed|stopped|failed)|awg_preflight_skipped|awg_transport_(?:unknown|unchanged|mark_changed|port_changed)|awg_post_udp_(?:unknown|no_send|no_reply|send_error|receive_error|bidirectional)|awg_control_(?:verified|not_warp|no_network|bind_failed|tcp_timeout|tcp_failed|tls_timeout|tls_failed|http_timeout|http_failed|wrong_path|path_no_syn|path_no_synack|path_no_write|path_no_ack|stopped)|awg_tcp_(?:unknown|no_syn|synack|rst|no_reply|source_mismatch|destination_mismatch|sequence_mismatch|bad_ip_checksum|bad_tcp_checksum|bad_format|tun_write_failed|synack_not_written|matched_no_ack|android_ack|android_rst|unrelated_reply)|awg_udp_(?:unknown|loop|no_send|no_reply|no_plaintext|bidirectional)|awg_data_(?:unknown|bad_out_checksum|bad_in_checksum|udp_error|no_tcp|no_client_data|server_data|server_ack|no_reply)|awg_flow_(?:unknown|no_tun_in|no_tun_out|bidirectional)|awg_country_(?:[A-Z]{2}|unknown)|awg_colo_(?:[A-Z]{3}|unknown)|awg_vpn_(?:doh_failed|node_rejected|region_ru|region_unknown|preflight_failed|existing_vpn|udp_loop|no_network|tcp_failed|tcp_timeout|wrong_path|tls_timeout|tls_certificate|tls_failed|http_timeout|http_failed|warp_missing|start_failed)|awg_(?:tun_create_failed|ipc_config_failed|endpoint_dns_failed|device_start_failed|no_handshake|https_timeout|tcp_timeout|tls_timeout|http_timeout|invalid_file|invalid_config|tunnel_failed|not_confirmed|https_failed|verified:[0-9]{1,5})")) }.orEmpty()
}

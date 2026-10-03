#!/bin/sh

NAME="air-ssid-check"
TARGET_DEVICE_ID="XXXXXXXXXX"

log() {
    logger -t "$NAME" "$1"
}

get_base_mac_suffix() {
    local mac_address=""

    mac_address=$(uci -q get aircnms.@aircnms[0].macaddr 2>/dev/null || true)
    if [ -n "$mac_address" ] && [ "$mac_address" != "XXXXXXXXXX" ]; then
        echo "$mac_address" | tr -d ':' | awk '{print toupper(substr($0, length($0)-5, 6))}'
        return 0
    fi

    for iface in eth0 wan eth1 lan; do
        [ -r "/sys/class/net/$iface/address" ] || continue
        mac_address=$(cat "/sys/class/net/$iface/address")
        [ -n "$mac_address" ] || continue
        echo "$mac_address" | tr -d ':' | awk '{print toupper(substr($0, length($0)-5, 6))}'
        return 0
    done

    return 1
}

check_device_id() {
    local device_id
    device_id=$(uci -q get aircnms.@aircnms[0].device_id 2>/dev/null)
    [ "$device_id" = "$TARGET_DEVICE_ID" ]
}

validate_ssid_config() {
    if [ "$(uci -q get aircnms.onboarding.operational_once 2>/dev/null)" = "1" ]; then
        log "Device operational_once=1. Validation complete (enrolled mode)."
        return 0
    fi

    if ! check_device_id; then
        log "Device ID does not match target. Skipping SSID validation."
        return 0
    fi

    local mac_suffix
    mac_suffix=$(get_base_mac_suffix) || {
        log "Base MAC not found"
        return 1
    }

    local default_ssid="Airpro_$mac_suffix"
    local wlan1_ssid="$(uci -q get wireless.wlan1.ssid)"
    local wlan2_ssid="$(uci -q get wireless.wlan2.ssid)"

    if [ "$wlan1_ssid" != "$default_ssid" ] || [ "$wlan2_ssid" != "$default_ssid" ]; then
        log "INFO: Current SSIDs (wlan1=$wlan1_ssid wlan2=$wlan2_ssid) differ from default ($default_ssid)"
    else
        log "SSID validation OK: factory default $default_ssid active on primary VAPs"
    fi
}

validate_ssid_config

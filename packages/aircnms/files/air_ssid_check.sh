#!/bin/sh

NAME="air-ssid-check"
TARGET_DEVICE_ID="XXXXXXXXXX"

log() {
    logger -t "$NAME" "$1"
}

# -----------------------------
# Get last 2 bytes of MAC
# -----------------------------
get_mac_suffix() {
    local iface="$1"
    [ -e "/sys/class/net/$iface/address" ] || return 1

    local mac_address
    mac_address=$(cat /sys/class/net/$iface/address)
    echo "$mac_address" | awk -F':' '{print toupper($5$6)}'
}

# -----------------------------
# Check device id
# -----------------------------
check_device_id() {
    local device_id
    device_id=$(uci get aircnms.@aircnms[0].device_id 2>/dev/null)

    [ "$device_id" = "$TARGET_DEVICE_ID" ]
}

# -----------------------------
# Main logic
# -----------------------------
apply_ssid_config() {

    if ! check_device_id; then
        log "Device ID does not match. Skipping SSID config."
        return 0
    fi

    sleep 3

    # 2.4 GHz
    local mac_suffix_phy0
    mac_suffix_phy0=$(get_mac_suffix phy0-ap0) || {
        log "Interface phy0-ap0 not found"
        return 1
    }

    local new_ssid_phy0="AIR-2G-$mac_suffix_phy0"
    uci set wireless.wlan1.ssid="$new_ssid_phy0"
    uci set wireless.wlan1.network="nat_network"

    # 5 GHz
    local mac_suffix_phy1
    mac_suffix_phy1=$(get_mac_suffix phy1-ap0) || {
        log "Interface phy1-ap0 not found"
        return 1
    }

    local new_ssid_phy1="AIR-5G-$mac_suffix_phy1"
    uci set wireless.wlan2.ssid="$new_ssid_phy1"
    uci set wireless.wlan2.network="nat_network"

    # Commit
    uci commit wireless

    log "SSID configured: $new_ssid_phy0 , $new_ssid_phy1"

    # Apply
    wifi reload
}

# -----------------------------
# Entry point
# -----------------------------
apply_ssid_config


#!/bin/sh

NAME="air-ssid-check"
TARGET_DEVICE_ID="XXXXXXXXXX"

log() {
    logger -t "$NAME" "$1"
}

# Get last 3 bytes / 6 hex digits from the base AP MAC.
# Both 2G and 5G default SSIDs intentionally use the same base suffix.
get_base_mac_suffix() {
    local mac_address=""

    mac_address=$(uci get aircnms.@aircnms[0].macaddr 2>/dev/null || true)
    if [ -n "$mac_address" ] && [ "$mac_address" != "XXXXXXXXXX" ]; then
        echo "$mac_address" | tr -d ':' | awk '{print toupper(substr($0, length($0)-5, 6))}'
        return 0
    fi

    for iface in wan eth1 lan eth0 phy0-ap0 phy1-ap0; do
        [ -e "/sys/class/net/$iface/address" ] || continue
        mac_address=$(cat "/sys/class/net/$iface/address")
        [ -n "$mac_address" ] || continue
        echo "$mac_address" | tr -d ':' | awk '{print toupper(substr($0, length($0)-5, 6))}'
        return 0
    done

    return 1
}

check_device_id() {
    local device_id
    device_id=$(uci get aircnms.@aircnms[0].device_id 2>/dev/null)
    [ "$device_id" = "$TARGET_DEVICE_ID" ]
}

apply_ssid_config() {
    if ! check_device_id; then
        log "Device ID does not match. Skipping SSID config."
        return 0
    fi

    sleep 3

    local mac_suffix
    mac_suffix=$(get_base_mac_suffix) || {
        log "Base MAC not found"
        return 1
    }

    local new_ssid_phy0="AirPro-2G-$mac_suffix"
    local new_ssid_phy1="AirPro-5G-$mac_suffix"

    uci set wireless.wlan1.ssid="$new_ssid_phy0"
    uci set wireless.wlan1.network="nat_network"
    uci set wireless.wlan2.ssid="$new_ssid_phy1"
    uci set wireless.wlan2.network="nat_network"
    uci commit wireless

    log "SSID configured: $new_ssid_phy0 , $new_ssid_phy1"
    wifi reload
}

apply_ssid_config

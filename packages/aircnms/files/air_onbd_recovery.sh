#!/bin/sh

NAME="air-onbd-recovery"
ACTION="$1"
MODE="$2"
STATE_DIR="/run/air-onbd"
INTENT="$STATE_DIR/recovery.intent"
APPLIED="$STATE_DIR/recovery.applied"
NET="nat_network"
RECOVERY_IP="192.168.23.1"
WAN_IF="lan"
WAN_FALLBACK_DEV="br-lan"
WAN_FALLBACK_IP="192.168.4.1"
WAN_FALLBACK_NETMASK="255.255.255.0"
SSID_PREFIX_2G="AirPro-2G"
SSID_PREFIX_5G="AirPro-5G"

log() { logger -t "$NAME" "$*"; }
uciq() { uci -q "$@"; }

operational_once() {
    [ "$(uci -q get aircnms.onboarding.operational_once 2>/dev/null)" = "1" ]
}


mac_suffix() {
    local mac=""
    for ifc in eth0 br-lan phy0-ap0; do
        [ -r "/sys/class/net/$ifc/address" ] && { mac=$(cat "/sys/class/net/$ifc/address"); break; }
    done
    [ -n "$mac" ] || mac="00:00:00:00:00:00"
    echo "$mac" | awk -F: '{print toupper($4$5$6)}'
}

first_radio() {
    local band="$1" r hw
    for r in $(uci -q show wireless | sed -n "s/^wireless\.\([^.=]*\)=wifi-device/\1/p"); do
        hw=$(uciq get wireless.$r.band)
        [ -z "$hw" ] && hw=$(uciq get wireless.$r.hwmode)
        case "$band:$hw" in
            2g:*2g*|2g:*11g*|2g:*11n*) echo "$r"; return 0 ;;
            5g:*5g*|5g:*11a*|5g:*11ac*|5g:*11ax*) echo "$r"; return 0 ;;
        esac
    done
    [ "$band" = 2g ] && echo radio0 || echo radio1
}

ensure_network() {
    uciq get network.$NET >/dev/null || uci set network.$NET=interface
    uci set network.$NET.proto='static'
    uci set network.$NET.ipaddr="$RECOVERY_IP"
    uci set network.$NET.netmask='255.255.255.0'

    uciq get dhcp.$NET >/dev/null || uci set dhcp.$NET=dhcp
    uci set dhcp.$NET.interface="$NET"
    uci set dhcp.$NET.start='50'
    uci set dhcp.$NET.limit='100'
    uci set dhcp.$NET.leasetime='15m'
    uci set dhcp.$NET.ignore='0'
}

ensure_wifi_iface() {
    local section="$1" radio="$2" ssid="$3" disabled="$4"
    uciq get wireless.$section >/dev/null || uci set wireless.$section=wifi-iface
    uci set wireless.$section.device="$radio"
    uci set wireless.$section.mode='ap'
    uci set wireless.$section.network="$NET"
    uci set wireless.$section.ssid="$ssid"
    uci set wireless.$section.encryption='none'
    uci set wireless.$section.hidden='0'
    uci set wireless.$section.disabled="$disabled"
}

remove_legacy_recovery_ifaces() {
    uciq delete wireless.aironbd2g || true
    uciq delete wireless.aironbd5g || true
    uciq delete wireless.airrec2g || true
    uciq delete wireless.airrec5g || true
}

remove_legacy_recovery_network() {
    uciq delete network.airrecovery || true
    uciq delete dhcp.airrecovery || true
}

apply_state() {
    local enable="$1" disabled suffix r2 r5
    disabled=1
    [ "$enable" = 1 ] && disabled=0
    suffix=$(mac_suffix)
    remove_legacy_recovery_network
    ensure_network
    remove_legacy_recovery_ifaces
    uci commit network
    uci commit dhcp
    uci commit wireless
    /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true
    wifi reload >/dev/null 2>&1 || true
    if [ "$enable" = 1 ]; then
        if operational_once; then
            log "recovery enable=1 preserve_wan=1 reason=operational_once network=$NET recovery_ip=$RECOVERY_IP ssid_suffix=$suffix"
        else
            uci set network.$WAN_IF.device="$WAN_FALLBACK_DEV"
            uci set network.$WAN_IF.proto='static'
            uci set network.$WAN_IF.ipaddr="$WAN_FALLBACK_IP"
            uci set network.$WAN_IF.netmask="$WAN_FALLBACK_NETMASK"
            uciq delete network.wan_fallback || true
            uci commit network
            ifup "$WAN_IF" >/dev/null 2>&1 || /etc/init.d/network reload >/dev/null 2>&1 || true
            log "recovery enable=1 preserve_wan=0 network=$NET recovery_ip=$RECOVERY_IP wan_if=$WAN_IF wan_fallback_ip=$WAN_FALLBACK_IP ssid_suffix=$suffix"
        fi
    else
        log "recovery enable=0 network=$NET recovery_ip=$RECOVERY_IP ssid_suffix=$suffix"
    fi
}

mkdir -p "$STATE_DIR"
case "$ACTION" in
    enable|disable) ;;
    *) echo "usage: $0 enable|disable [shadow|apply]" >&2; exit 2 ;;
esac
printf '%s mode=%s\n' "$ACTION" "${MODE:-shadow}" > "$INTENT"
[ "$MODE" = "apply" ] || exit 0
[ -f "$APPLIED" ] && [ "$(cat "$APPLIED" 2>/dev/null)" = "$ACTION" ] && exit 0
[ "$ACTION" = "enable" ] && apply_state 1 || apply_state 0
echo "$ACTION" > "$APPLIED"

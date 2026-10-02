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
WAN_FALLBACK_IP="192.168.188.253"
WAN_FALLBACK_NETMASK="255.255.255.0"

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
    [ "$band" = 2g ] && echo wifi1 || echo wifi0
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
    uciq delete wireless.airrec2g || true
    uciq delete wireless.airrec5g || true
    uciq delete wireless.aironbd2g || true
    uciq delete wireless.aironbd5g || true
}

remove_legacy_recovery_network() {
    uciq delete network.airrecovery || true
    uciq delete dhcp.airrecovery || true
}

apply_state() {
    local enable="$1" suffix r2 r5
    suffix=$(mac_suffix)
    r2=$(first_radio 2g)
    r5=$(first_radio 5g)

    if [ "$enable" = 1 ]; then
        if operational_once; then
            log "recovery enable=1 suppressed reason=operational_once"
            remove_legacy_recovery_ifaces
            uci commit wireless
            wifi reload >/dev/null 2>&1 || true
            return 0
        fi

        remove_legacy_recovery_network
        remove_legacy_recovery_ifaces
        ensure_wifi_iface "airrec2g" "$r2" "Airpro_${suffix}" 0
        ensure_wifi_iface "airrec5g" "$r5" "Airpro_${suffix}" 0
        uci commit wireless
        wifi reload >/dev/null 2>&1 || true

        # WAN Fallback IP (only set on br-lan if not already set)
        if [ "$(uciq get network.$WAN_IF.proto)" != "static" ] || [ "$(uciq get network.$WAN_IF.ipaddr)" != "$WAN_FALLBACK_IP" ]; then
            uci set network.$WAN_IF.proto='static'
            uci set network.$WAN_IF.ipaddr="$WAN_FALLBACK_IP"
            uci set network.$WAN_IF.netmask="$WAN_FALLBACK_NETMASK"
            uciq delete network.wan_fallback || true
            uci commit network
            ifup "$WAN_IF" >/dev/null 2>&1 || /etc/init.d/network reload >/dev/null 2>&1 || true
        fi
        log "recovery enable=1 applied recovery_ip=$RECOVERY_IP wan_if=$WAN_IF wan_fallback_ip=$WAN_FALLBACK_IP ssid=Airpro_$suffix"
    else
        remove_legacy_recovery_ifaces
        uci commit wireless
        wifi reload >/dev/null 2>&1 || true

        if ! operational_once; then
            if [ "$(uciq get network.$WAN_IF.proto)" = "static" ] && [ "$(uciq get network.$WAN_IF.ipaddr)" = "$WAN_FALLBACK_IP" ]; then
                uci set network.$WAN_IF.proto='dhcp'
                uciq delete network.$WAN_IF.ipaddr || true
                uciq delete network.$WAN_IF.netmask || true
                uci commit network
                ifup "$WAN_IF" >/dev/null 2>&1 || /etc/init.d/network reload >/dev/null 2>&1 || true
            fi
        fi
        log "recovery enable=0 applied"
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

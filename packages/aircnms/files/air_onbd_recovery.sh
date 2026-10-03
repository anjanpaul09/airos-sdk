#!/bin/sh

NAME="air-onbd-recovery"
ACTION="$1"
MODE="$2"
STATE_DIR="/run/air-onbd"
INTENT="$STATE_DIR/recovery.intent"
APPLIED="$STATE_DIR/recovery.applied"
WAN_IF="lan"
WAN_FALLBACK_IP="192.168.188.253"
WAN_FALLBACK_NETMASK="255.255.255.0"

log() { logger -t "$NAME" "$*"; }
uciq() { uci -q "$@"; }

operational_once() {
    [ "$(uci -q get aircnms.onboarding.operational_once 2>/dev/null)" = "1" ]
}

get_dhcp_ip() {
    ubus call network.interface.lan status 2>/dev/null | jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null
}

has_active_dhcp_ip() {
    local ip
    ip="$(get_dhcp_ip)"
    [ -n "$ip" ] && [ "$ip" != "$WAN_FALLBACK_IP" ]
}

apply_state() {
    case "$1" in
        1)
            if operational_once; then
                log "recovery enable=1 suppressed reason=operational_once"
                return 0
            fi

            if has_active_dhcp_ip; then
                log "DHCP active ($(get_dhcp_ip)); fallback IP not required"
                if [ "$(uciq get aircnms.onboarding.in_fallback)" = "1" ]; then
                    uciq delete aircnms.onboarding.in_fallback
                    uciq commit aircnms
                fi
                return 0
            fi

            # Check if lan is already configured with fallback IP
            if [ "$(uciq get network.$WAN_IF.proto)" != "static" ] || [ "$(uciq get network.$WAN_IF.ipaddr)" != "$WAN_FALLBACK_IP" ]; then
                # Tag this static IP as temporary recovery fallback
                uci set aircnms.onboarding.in_fallback='1'
                uci commit aircnms

                uci set network.$WAN_IF.proto='static'
                uci set network.$WAN_IF.ipaddr="$WAN_FALLBACK_IP"
                uci set network.$WAN_IF.netmask="$WAN_FALLBACK_NETMASK"
                uciq delete network.wan_fallback || true
                uci commit network

                /sbin/ifup "$WAN_IF" >/dev/null 2>&1 || true
                log "recovery enable=1 applied: lan switched to static fallback $WAN_FALLBACK_IP in UCI"
            fi
            ;;
        0)
            # Revert to DHCP if we were in recovery fallback
            local was_fallback=0
            if [ "$(uciq get aircnms.onboarding.in_fallback)" = "1" ] || \
               ([ "$(uciq get network.$WAN_IF.proto)" = "static" ] && [ "$(uciq get network.$WAN_IF.ipaddr)" = "$WAN_FALLBACK_IP" ]); then
                was_fallback=1
            fi

            if [ "$was_fallback" = "1" ]; then
                uci set network.$WAN_IF.proto='dhcp'
                uciq delete network.$WAN_IF.ipaddr
                uciq delete network.$WAN_IF.netmask
                uciq delete network.wan_fallback || true
                uci commit network

                uciq delete aircnms.onboarding.in_fallback
                uci commit aircnms

                /sbin/ifup "$WAN_IF" >/dev/null 2>&1 || true
                log "recovery enable=0 applied: lan reverted to dhcp in UCI"
            fi
            ;;
    esac
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

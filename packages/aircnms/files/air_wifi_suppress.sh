#!/bin/sh
# air_wifi_suppress.sh - Suppresses Wi-Fi broadcasting during cloud outage on provisioned AP
#
# When a provisioned AP loses cloud connectivity past the 60s grace period:
# 1. Backs up current cloud-configured wireless settings to /etc/config/wireless.cloud_backup
# 2. Sets disabled='1' on all active wifi-ifaces to stop radio beacons
# 3. Signals /run/air-onbd/wifi_suppressed so LED renders Solid Amber
#
# When cloud connectivity is restored:
# 1. Restores /etc/config/wireless from backup
# 2. Re-enables Wi-Fi beacons
# 3. Clears flag so LED returns to Solid Blue

ACTION="$1"
STATE_DIR="/run/air-onbd"
FLAG="$STATE_DIR/wifi_suppressed"
BACKUP="/etc/config/wireless.cloud_backup"

mkdir -p "$STATE_DIR"

case "$ACTION" in
    suppress)
        [ -f "$FLAG" ] && exit 0
        logger -t air-wifi-suppress "Cloud outage grace expired (60s): corporate Wi-Fi suppressed (radios quiet)"
        
        # Backup current wireless config if backup doesn't exist yet
        [ ! -f "$BACKUP" ] && cp -p /etc/config/wireless "$BACKUP"
        touch "$FLAG"
        
        changed=0
        for s in $(uci -q show wireless | sed -n "s/^wireless\.\([^.=]*\)=wifi-iface/\1/p"); do
            # Do not touch recovery interfaces if any exist
            case "$s" in
                airrec*|aironbd*) continue ;;
            esac
            if [ "$(uci -q get wireless.$s.disabled)" != "1" ]; then
                uci set wireless.$s.disabled='1'
                changed=1
            fi
        done
        
        if [ "$changed" = 1 ]; then
            uci commit wireless
            wifi reload >/dev/null 2>&1 || true
        fi
        ;;

    restore)
        if [ ! -f "$FLAG" ] && [ ! -f "$BACKUP" ]; then
            exit 0
        fi
        logger -t air-wifi-suppress "Cloud connectivity restored: corporate Wi-Fi re-enabled"
        rm -f "$FLAG"
        
        if [ -f "$BACKUP" ]; then
            cp -p "$BACKUP" /etc/config/wireless
            rm -f "$BACKUP"
            uci commit wireless
            wifi reload >/dev/null 2>&1 || true
        else
            # Backup was consumed or updated by netconfd, just ensure disabled=0
            changed=0
            for s in $(uci -q show wireless | sed -n "s/^wireless\.\([^.=]*\)=wifi-iface/\1/p"); do
                case "$s" in
                    airrec*|aironbd*) continue ;;
                esac
                if [ "$(uci -q get wireless.$s.disabled)" = "1" ]; then
                    uci set wireless.$s.disabled='0'
                    changed=1
                fi
            done
            if [ "$changed" = 1 ]; then
                uci commit wireless
                wifi reload >/dev/null 2>&1 || true
            fi
        fi
        ;;

    status)
        [ -f "$FLAG" ] && echo "suppressed" || echo "active"
        ;;

    *)
        echo "Usage: $0 suppress|restore|status" >&2
        exit 1
        ;;
esac

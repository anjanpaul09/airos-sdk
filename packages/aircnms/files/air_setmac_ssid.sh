#!/bin/sh

RAW_MAC=""
MAC=$(uci -q get aircnms.@aircnms[0].macaddr 2>/dev/null || true)
if [ -n "$MAC" ] && [ "$MAC" != "XXXXXXXXXX" ]; then
    CLEAN_MAC=$(echo "$MAC" | tr -d ':- ' | tr 'a-f' 'A-F')
    [ ${#CLEAN_MAC} -eq 12 ] && RAW_MAC="$CLEAN_MAC"
fi

if [ -z "$RAW_MAC" ]; then
    for iface in eth0 wan eth1 lan; do
        if [ -r "/sys/class/net/$iface/address" ]; then
            CLEAN_MAC=$(cat "/sys/class/net/$iface/address" 2>/dev/null | tr -d ':- ' | tr 'a-f' 'A-F')
            [ ${#CLEAN_MAC} -eq 12 ] && { RAW_MAC="$CLEAN_MAC"; break; }
        fi
    done
fi

[ -n "$RAW_MAC" ] || exit 0

# Extract 2-char hex bytes cleanly
b1=$(echo "$RAW_MAC" | cut -c1-2)
b2=$(echo "$RAW_MAC" | cut -c3-4)
b3=$(echo "$RAW_MAC" | cut -c5-6)
b4=$(echo "$RAW_MAC" | cut -c7-8)
b5=$(echo "$RAW_MAC" | cut -c9-10)
b6=$(echo "$RAW_MAC" | cut -c11-12)

BASE_FORMATTED="$b1:$b2:$b3:$b4:$b5:$b6"
echo "Base MAC: $BASE_FORMATTED"

# Explicitly pin br-lan MAC from /sys/class/net/wan/address to prevent bridge MAC shifting
WAN_MAC=""
if [ -r "/sys/class/net/wan/address" ]; then
    WAN_MAC=$(cat "/sys/class/net/wan/address" 2>/dev/null | tr 'A-F' 'a-f' | tr -d ' \t\r\n')
fi
if [ -z "$WAN_MAC" ] && [ -n "$BASE_FORMATTED" ]; then
    WAN_MAC=$(echo "$BASE_FORMATTED" | tr 'A-F' 'a-f')
fi

if [ -n "$WAN_MAC" ]; then
    dev_sec=$(uci show network 2>/dev/null | grep "\.name='br-lan'" | cut -d. -f2 | cut -d= -f1)
    net_mod=0
    if [ -n "$dev_sec" ] && [ "$(uci -q get network.$dev_sec.macaddr)" != "$WAN_MAC" ]; then
        echo "Setting br-lan device MAC -> $WAN_MAC"
        uci set network.$dev_sec.macaddr="$WAN_MAC"
        net_mod=1
    fi
    if [ "$(uci -q get network.lan.macaddr)" != "$WAN_MAC" ]; then
        echo "Setting lan interface MAC -> $WAN_MAC"
        uci set network.lan.macaddr="$WAN_MAC"
        net_mod=1
    fi
    if [ "$net_mod" = "1" ]; then
        uci commit network
    fi
    cur_br_mac=$(cat /sys/class/net/br-lan/address 2>/dev/null | tr 'A-F' 'a-f')
    if [ -n "$cur_br_mac" ] && [ "$cur_br_mac" != "$WAN_MAC" ]; then
        ip link set dev br-lan address "$WAN_MAC" 2>/dev/null || true
    fi
fi

# Convert last byte to decimal
last=$(printf "%d" 0x$b6)

index=0
changed=0

for iface in $(uci show wireless 2>/dev/null | grep "=wifi-iface" | cut -d. -f2 | cut -d= -f1); do
    slot=$(echo "$iface" | tr -dc '0-9')
    if [ -n "$slot" ] && [ "$slot" -ge 1 ] 2>/dev/null; then
        idx=$((slot - 1))
    else
        idx=$index
    fi
    new_last=$(printf "%02x" $(( (last + idx) % 256 )))
    NEW_MAC="$(echo "$b1:$b2:$b3:$b4:$b5:$new_last" | tr 'A-F' 'a-f')"

    if [ "$(uci -q get wireless.$iface.macaddr)" != "$NEW_MAC" ]; then
        echo "Setting $iface -> $NEW_MAC"
        uci set wireless.$iface.macaddr="$NEW_MAC"
        changed=1
    fi

    index=$((index + 1))
done

if [ "$changed" = "1" ]; then
    uci commit wireless
    if [ "$1" != "--no-reload" ]; then
        wifi reload
    fi
else
    echo "Wireless MACs already match base MAC, skipping reload"
fi

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

# Convert last byte to decimal
last=$(printf "%d" 0x$b6)

index=0
changed=0

for iface in $(uci show wireless 2>/dev/null | grep "=wifi-iface" | cut -d. -f2 | cut -d= -f1); do
    new_last=$(printf "%02x" $(( (last + index) % 256 )))
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

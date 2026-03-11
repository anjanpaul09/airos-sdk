#!/bin/sh

BASE_IF="eth0"

BASE_MAC=$(cat /sys/class/net/$BASE_IF/address)

echo "Base MAC: $BASE_MAC"

# split mac safely
b1=$(echo $BASE_MAC | cut -d: -f1)
b2=$(echo $BASE_MAC | cut -d: -f2)
b3=$(echo $BASE_MAC | cut -d: -f3)
b4=$(echo $BASE_MAC | cut -d: -f4)
b5=$(echo $BASE_MAC | cut -d: -f5)
b6=$(echo $BASE_MAC | cut -d: -f6)

# convert last byte to decimal
last=$(printf "%d" 0x$b6)

index=0

for iface in $(uci show wireless | grep "=wifi-iface" | cut -d. -f2 | cut -d= -f1); do

    new_last=$(printf "%02x" $((last + index)))

    NEW_MAC="$b1:$b2:$b3:$b4:$b5:$new_last"

    echo "Setting $iface -> $NEW_MAC"

    uci set wireless.$iface.macaddr="$NEW_MAC"

    index=$((index + 1))

done

uci commit wireless

wifi reload


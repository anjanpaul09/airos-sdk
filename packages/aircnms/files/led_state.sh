#!/bin/sh
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
# Optimized LED status indicator for OpenWrt (production use)
# Compatible with BusyBox (no float sleep), minimal CPU/memory

# --- Configuration ---
RED=/sys/class/leds/system/brightness
GREEN=/sys/class/leds/wlan2g/brightness
BLUE=/sys/class/leds/wlan5g/brightness

DEBUG=0  # Set to 1 only for debugging (adds overhead)

# Ensure LED sysfs files exist
[ -w "$RED" ]   || exit 1
[ -w "$GREEN" ] || exit 1
[ -w "$BLUE" ]  || exit 1

# --- Global State ---
BOOTED=0
CLOUD_OK=0
INTERNET_OK=0
RED_BLINK_STATE=0

# --- Helpers ---
debug_print() {
	[ "$DEBUG" = "1" ] && echo "[DEBUG] $1" >&2
}

off_all() {
	echo 0 > "$RED"
	echo 0 > "$GREEN"
	echo 0 > "$BLUE"
}

on_red()   { echo 255 > "$RED"; }
on_green() { echo 255 > "$GREEN"; }
on_blue()  { echo 255 > "$BLUE"; }

blink_red() {
	if [ "$RED_BLINK_STATE" -eq 0 ]; then
		echo 255 > "$RED"
		RED_BLINK_STATE=1
	else
		echo 0 > "$RED"
		RED_BLINK_STATE=0
	fi
}

# Only check boot once until success
check_boot() {
	if [ "$BOOTED" = "1" ]; then
		return 0
	fi
	if hostapd_cli -i phy0-ap0 status 2>/dev/null | grep -q "state=ENABLED" &&
	   hostapd_cli -i phy1-ap0 status 2>/dev/null | grep -q "state=ENABLED"; then
		BOOTED=1
		debug_print "Boot complete"
		return 0
	fi
	return 1
}

# Light internet check: 1s timeout, quiet
check_internet() {
	ping -c 1 -W 1 -q 8.8.8.8 >/dev/null 2>&1
}

# Cache cloud status; re-check only if needed
check_cloud() {
	[ "$(uci -q get aircnms.@aircnms[0].online)" = "1" ]
}

# --- Main LED logic ---
update_led() {
	if ! check_boot; then
		off_all
		on_red
		return
	fi

	if ! check_internet; then
		echo 0 > "$GREEN"
		echo 0 > "$BLUE"
		blink_red
		return
	fi

	if ! check_cloud; then
		off_all
		on_green
		return
	fi

	# All good
	off_all
	on_blue
}

# --- Signal cleanup ---
cleanup() {
	off_all
	exit 0
}
trap cleanup INT TERM

# --- Main loop ---
debug_print "LED controller started"
while true; do
	update_led

	# Adaptive sleep: blink faster when internet down, else slow poll
	if [ "$BOOTED" = "1" ] && ! check_internet; then
		sleep 1  # blink every 1s (on/off each cycle)
	else
		sleep 3  # normal poll every 3s
	fi
done

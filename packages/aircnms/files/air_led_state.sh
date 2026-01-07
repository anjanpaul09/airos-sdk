#!/bin/sh
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# =========================================================
#  AirPro LED Status Controller (Production)
# =========================================================

NAME="air-led"
DEBUG=0

# --- LED paths ---
RED="/sys/class/leds/system/brightness"
GREEN="/sys/class/leds/wlan2g/brightness"
BLUE="/sys/class/leds/wlan5g/brightness"

# --- Sanity check ---
[ -w "$RED" ]   || exit 1
[ -w "$GREEN" ] || exit 1
[ -w "$BLUE" ]  || exit 1

# --- State ---
RED_BLINK_STATE=0

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
log() {
	[ "$DEBUG" = "1" ] && logger -t "$NAME" "$1"
}

off_all() {
	echo 0 > "$RED"
	echo 0 > "$GREEN"
	echo 0 > "$BLUE"
}

on_red()   { echo 255 > "$RED"; }
on_green() { echo 255 > "$GREEN"; }
on_blue()  { echo 255 > "$BLUE"; }

RED_BLINK_STATE=0

blink_red() {
	if [ "$RED_BLINK_STATE" -eq 0 ]; then
		echo 255 > "$RED"
		RED_BLINK_STATE=1
	else
		echo 0 > "$RED"
		RED_BLINK_STATE=0
	fi
}


# ---------------------------------------------------------
# BOOT CHECK
# System is considered ready when ubus is alive
# ---------------------------------------------------------
check_boot() {
	ubus call system info >/dev/null 2>&1
}

# ---------------------------------------------------------
# INTERNET CHECK
# Route existence (no ping, no ICMP dependency)
# ---------------------------------------------------------
check_internet() {
	ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1
}

# ---------------------------------------------------------
# CLOUD CHECK
# Your CNMS status flag
# ---------------------------------------------------------
check_cloud() {
	[ "$(uci -q get aircnms.@aircnms[0].online)" = "1" ]
}

# ---------------------------------------------------------
# LED STATE MACHINE
# ---------------------------------------------------------
update_led() {

	# 1. System not ready
	if ! check_boot; then
		off_all
		on_red
		return
	fi

	# 2. No internet route
	if ! check_internet; then
		off_all
		blink_red
		return
	fi

	# 3. Internet OK, cloud down
	if ! check_cloud; then
		off_all
		on_green
		return
	fi

	# 4. All good
	off_all
	on_blue
}

# ---------------------------------------------------------
# Cleanup on stop
# ---------------------------------------------------------
cleanup() {
	off_all
	exit 0
}
trap cleanup INT TERM

# ---------------------------------------------------------
# Main loop
# ---------------------------------------------------------
log "LED controller started"

while true; do
	update_led

	# Fast blink when internet is down, else slow poll
	if ! check_internet; then
		sleep 1
	else
		sleep 3
	fi
done


#!/bin/sh
# MT7621 renderer only. air-onbd owns onboarding state and policy.
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
R=/sys/class/leds/system
G=/sys/class/leds/wlan2g
B=/sys/class/leds/wlan5g
for d in "$R" "$G" "$B"; do [ -w "$d/brightness" ] || exit 1; done
last=
phase=0
none(){ printf none >"$1/trigger"; printf 0 >"$1/brightness"; }
reset(){ none "$R"; none "$G"; none "$B"; }
on(){ printf 1 >"$1/brightness"; }
timer(){
    printf timer >"$1/trigger"
    n=0
    while { [ ! -w "$1/delay_on" ] || [ ! -w "$1/delay_off" ]; } && [ "$n" -lt 10 ]; do
        sleep 1
        n=$((n+1))
    done
    [ -w "$1/delay_on" ] && [ -w "$1/delay_off" ] || return 1
    printf "$2" >"$1/delay_on"
    printf "$3" >"$1/delay_off"
}
apply_state(){
    reset
    case "$1" in
        OPERATIONAL) on "$B" ;;
        OPERATIONAL_DEGRADED) on "$G" ;;
        INIT|INITIALIZING|BOOTING) on "$R" ;;
        DHCP_WAIT) ;;
        NO_LINK) timer "$R" 200 800 ;;
        DHCP_FAILED|NO_DEFAULT_ROUTE|DNS_FAILED|INTERNET_UNREACHABLE) on "$R"; on "$G" ;;
        CLAIM_REQUIRED|PENDING_CLAIM) ;;
        UNKNOWN_DEVICE) on "$G"; timer "$R" 750 750 ;;
        CONFIG_APPLYING) on "$G"; on "$B"; timer "$R" 250 250 ;;
        CONFIG_FAILED|ROLLBACK) timer "$R" 500 500 ;;
        ENROLLED) on "$B" ;;
    esac
}
cleanup(){ reset; exit 0; }
trap cleanup INT TERM
while :; do
    state="$(ubus call air.onboarding status 2>/dev/null | jsonfilter -e '@.visible_state' 2>/dev/null)"
    if [ "$state" != "$last" ]; then apply_state "$state"; last="$state"; fi
    case "$state" in
        CLOUD_UNREACHABLE|MQTT_DISCONNECTED)
            phase=$((1-phase)); reset
            [ "$phase" = 1 ] && on "$B" || on "$R"
            ;;
        CONFIG_QUEUED|CONFIG_VERIFYING)
            phase=$((1-phase)); reset
            [ "$phase" = 1 ] && on "$B" || on "$G"
            ;;
        DHCP_WAIT|CLAIM_REQUIRED|PENDING_CLAIM)
            phase=$((1-phase)); reset
            [ "$phase" = 1 ] && on "$B"
            ;;
        OPERATIONAL_DEGRADED)
            phase=$((1-phase)); reset; on "$G"
            [ "$phase" = 1 ] && on "$B"
            ;;
    esac
    sleep 1
done

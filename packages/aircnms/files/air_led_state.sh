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
    printf timer >"$1/trigger" 2>/dev/null || return 1
    if [ -w "$1/delay_on" ] && [ -w "$1/delay_off" ]; then
        printf "$2" >"$1/delay_on"
        printf "$3" >"$1/delay_off"
        return 0
    fi
    return 1
}
apply_state(){
    reset
    case "$1" in
        OPERATIONAL|ENROLLED) on "$B" ;;
        INIT|INITIALIZING|BOOTING) on "$R" ;;
        CLOUD_CONNECTING) timer "$B" 150 150 || on "$B" ;;
        NO_LINK) timer "$R" 200 800 || on "$R" ;;
        DHCP_FAILED|NO_DEFAULT_ROUTE|DNS_FAILED|INTERNET_UNREACHABLE) on "$R"; on "$G" ;;
        CONFIG_APPLYING) timer "$R" 200 200 && timer "$B" 200 200 || reset ;;
        CONFIG_FAILED|ROLLBACK|CONFIG_ROLLED_BACK) timer "$R" 500 500 || on "$R" ;;
        DHCP_WAIT|CLAIM_REQUIRED|PENDING_CLAIM|UNKNOWN_DEVICE|CLOUD_UNREACHABLE|MQTT_DISCONNECTED|OPERATIONAL_DEGRADED|CONFIG_QUEUED|CONFIG_VERIFYING|CONFIG_DOWNLOADING) ;;
    esac
}
cleanup(){ reset; exit 0; }
trap cleanup INT TERM
if [ -n "$1" ]; then
    apply_state "$1"
    exit 0
fi
while :; do
    state="$(ubus call air.onboarding status 2>/dev/null | jsonfilter -e '@.visible_state' 2>/dev/null)"
    [ -z "$state" ] && state="UNKNOWN"
    if [ "$state" != "$last" ]; then apply_state "$state"; last="$state"; fi
    case "$state" in
        DHCP_WAIT)
            phase=$((1-phase)); reset
            [ "$phase" = 1 ] && { on "$R"; on "$G"; }
            ;;
        CONFIG_APPLYING)
            if [ ! -w "$R/delay_on" ] || [ ! -w "$B/delay_on" ]; then
                phase=$((1-phase)); reset
                [ "$phase" = 1 ] && { on "$R"; on "$B"; }
            fi
            ;;
        CLOUD_UNREACHABLE|MQTT_DISCONNECTED|OPERATIONAL_DEGRADED)
            if [ -f /run/air-onbd/wifi_suppressed ]; then
                reset; on "$R"; on "$G"
            else
                phase=$((1-phase)); reset
                [ "$phase" = 1 ] && on "$B" || { on "$R"; on "$G"; }
            fi
            ;;
        CLAIM_REQUIRED|PENDING_CLAIM|UNKNOWN_DEVICE)
            phase=$((1-phase)); reset
            [ "$phase" = 1 ] && on "$B"
            ;;
        CONFIG_QUEUED|CONFIG_VERIFYING|CONFIG_DOWNLOADING)
            phase=$((1-phase)); reset
            [ "$phase" = 1 ] && on "$B" || on "$G"
            ;;
    esac
    sleep 1
done

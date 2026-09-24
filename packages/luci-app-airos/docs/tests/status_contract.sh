#!/bin/sh

set -eu

TMP="${TMPDIR:-/tmp}/airui-status-contract.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

capture() {
	ubus call airui.status "$1" > "$TMP/$1.json" || fail "airui.status $1 call failed"
	[ "$(jsonfilter -i "$TMP/$1.json" -e '@.ok')" = "true" ] || fail "$1 returned ok=false"
}

value() {
	jsonfilter -i "$TMP/$1.json" -e "$2"
}

close_enough() {
	left="$1"
	right="$2"
	tolerance="$3"
	difference=$((left - right))
	[ "$difference" -lt 0 ] && difference=$((-difference))
	[ "$difference" -le "$tolerance" ]
}

for method in summary device_status clients statistics; do
	capture "$method"
done

summary_uptime="$(value summary '@.data.system.uptime')"
summary_memory="$(value summary '@.data.system.memory.total')"
summary_load="$(value summary '@.data.system.load[0]')"

for method in device_status clients statistics; do
	uptime="$(value "$method" '@.data.system.uptime')"
	memory="$(value "$method" '@.data.system.memory.total')"
	load="$(value "$method" '@.data.system.load[0]')"

	close_enough "$summary_uptime" "$uptime" 2 || fail "$method uptime differs from summary"
	[ "$summary_memory" = "$memory" ] || fail "$method memory total differs from summary"
	close_enough "$summary_load" "$load" 65536 || fail "$method one-minute load differs by more than 1.00"
done

station_dump="$(value clients '@.data.wireless_stations')"
station_count="$(printf '%s\n' "$station_dump" | sed -n 's/^interface [^ ]* \([0-9A-Fa-f:]\{17\}\)$/\1/p' | tr 'a-f' 'A-F' | sort -u | wc -l)"
identity_count="$(value clients '@.data.client_identities' | grep -c '"found": true' || true)"
[ "$identity_count" -ge "$station_count" ] || fail "not every wireless station has an identity result"

for method in summary statistics; do
	proc_stat="$(value "$method" '@.data.proc_stat')"
	proc_cpuinfo="$(value "$method" '@.data.proc_cpuinfo')"
	printf '%s\n' "$proc_stat" | grep -q '^cpu ' || fail "$method does not expose aggregate CPU counters"
	cores="$(printf '%s\n' "$proc_cpuinfo" | sed -n 's/^core[[:space:]]*:[[:space:]]*//p' | sort -u | wc -l)"
	[ "$cores" -gt 0 ] || cores="$(printf '%s\n' "$proc_cpuinfo" | grep -c '^processor[[:space:]]*:' || true)"
	[ "$cores" -gt 0 ] || fail "$method does not expose a physical CPU inventory"
	if [ "$method" = summary ]; then
		summary_cores="$cores"
	else
		[ "$cores" = "$summary_cores" ] || fail "statistics core count differs from summary"
	fi
done

ubus call airui.status client_disconnect '{"macaddr":"invalid"}' > "$TMP/disconnect.json" || true
[ "$(jsonfilter -i "$TMP/disconnect.json" -e '@.ok')" = "false" ] || fail "invalid disconnect MAC was accepted"
[ "$(jsonfilter -i "$TMP/disconnect.json" -e '@.errors[0].code')" = "invalid_argument" ] || fail "invalid disconnect error code is inconsistent"

echo "PASS: AirUI status contracts are consistent ($station_count wireless station(s), $summary_cores CPU core(s))"

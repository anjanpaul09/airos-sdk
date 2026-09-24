#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
status="$root/platform/mt76/luci/modules/luci-mod-status/htdocs/luci-static/resources/view/status"
acl="$root/platform/mt76/luci/modules/luci-mod-status/root/usr/share/rpcd/acl.d/airui-status.json"
backend="$root/../aircnms/src/managers/airuid/src/airui_ubus.c"

views="airui_dashboard_v11.js airui_device_status_v10.js airui_device_statistics_v8.js airui_clients_v19.js"

for view in $views; do
	if ! grep -q "method: 'snapshot'" "$status/$view"; then
		echo "FAIL: $view does not use the shared status snapshot" >&2
		exit 1
	fi
	if grep -Eq "method: '(summary|overview|device_status|clients|statistics)'" "$status/$view"; then
		echo "FAIL: $view still declares a legacy status read endpoint" >&2
		exit 1
	fi
done

grep -q '"snapshot"' "$acl" || { echo 'FAIL: snapshot ACL missing' >&2; exit 1; }
grep -q 'UBUS_METHOD_NOARG("snapshot"' "$backend" || { echo 'FAIL: snapshot UBUS method missing' >&2; exit 1; }

echo 'PASS: all active Status views use the canonical backend snapshot'

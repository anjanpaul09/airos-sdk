#!/bin/sh
set -eu

AP="${AP:-192.168.1.7}"
PORT="${PORT:-3041}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/platform/mt76/luci/modules/luci-mod-status"
THEME="$ROOT/platform/mt76/luci/themes/luci-theme-airui/htdocs/luci-static/airui/custom.css"
SCP_OPTS="-O -P $PORT"

echo "Deploying device statistics v10 + theme CSS to root@${AP}:${PORT} ..."

scp $SCP_OPTS \
	"$SRC/htdocs/luci-static/resources/view/status/airui_device_statistics_v10.js" \
	"root@${AP}:/www/luci-static/resources/view/status/"

scp $SCP_OPTS \
	"$SRC/root/usr/share/luci/menu.d/luci-mod-status.json" \
	"root@${AP}:/usr/share/luci/menu.d/luci-mod-status.json"

scp $SCP_OPTS \
	"$THEME" \
	"root@${AP}:/www/luci-static/airui/custom.css"

ssh -p "$PORT" "root@${AP}" '
	rm -rf /tmp/luci-* /tmp/luci-modulecache /tmp/luci-indexcache
	/etc/init.d/rpcd restart
	/etc/init.d/uhttpd restart
	grep -q stats-live-chart /www/luci-static/resources/view/status/airui_device_statistics_v10.js \
		&& echo "OK: v10 live-traffic chart wrapper present" \
		|| echo "FAIL: v10 missing stats-live-chart"
	grep -q stats-live-y-label /www/luci-static/airui/custom.css \
		&& echo "OK: theme CSS for Y-axis label present" \
		|| echo "FAIL: custom.css missing stats-live-y-label"
	grep device_statistics_v10 /usr/share/luci/menu.d/luci-mod-status.json
'

echo "Done. Hard refresh Device Statistics (Ctrl+Shift+R)."

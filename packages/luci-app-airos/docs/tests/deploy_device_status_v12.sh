#!/bin/sh
set -eu

AP="${AP:-192.168.1.7}"
PORT="${PORT:-3041}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SRC="$ROOT/platform/mt76/luci/modules/luci-mod-status"
THEME="$ROOT/platform/mt76/luci/themes/luci-theme-airui/htdocs/luci-static/airui/custom.css"

SCP_OPTS="-O -P $PORT"

echo "Deploying device status v12 to root@${AP}:${PORT} ..."

scp $SCP_OPTS \
	"$SRC/htdocs/luci-static/resources/view/status/airui_device_status_v12.js" \
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
	grep -q joinBandValues /www/luci-static/resources/view/status/airui_device_status_v12.js \
		&& echo "OK: v12 grouped SSID logic present" \
		|| echo "FAIL: v12 file missing grouped SSID logic"
	grep device_status_v12 /usr/share/luci/menu.d/luci-mod-status.json
'

echo "Done. Hard refresh browser (Ctrl+Shift+R) on Device Status page."

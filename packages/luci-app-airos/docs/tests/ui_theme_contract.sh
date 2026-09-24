#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
THEME="$ROOT/platform/mt76/luci/themes/luci-theme-airui"
CSS="$THEME/htdocs/luci-static/airui/reference.css"
HEADER="$THEME/ucode/template/themes/airui/header.ut"
FOOTER="$THEME/ucode/template/themes/airui/footer.ut"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

require_text() {
	file="$1"
	pattern="$2"
	grep -q "$pattern" "$file" || fail "$file is missing: $pattern"
}

require_view_signal() {
	file="$1"
	shift
	for signal in "$@"; do
		require_text "$file" "$signal"
	done
}

require_text "$HEADER" 'reference.css?v=airui-production-theme-'
require_text "$FOOTER" 'airui-site-footer'
require_text "$CSS" '#fef0e7'
require_text "$CSS" '#f58634'
require_text "$CSS" 'icons/activity.svg'
require_text "$CSS" 'icons/network-nav.svg'
require_text "$CSS" 'icons/settings.svg'
require_text "$CSS" 'icons/shield-check.svg'
require_text "$CSS" 'icons/wrench.svg'
require_text "$CSS" 'text-decoration: none !important'
require_text "$CSS" 'is-loading'
require_text "$CSS" 'is-empty'
require_text "$CSS" 'is-success'
require_text "$CSS" 'is-failure'
require_text "$CSS" 'is-applying'
require_text "$CSS" 'is-rollback'
require_text "$CSS" 'is-stale'

APPLY_STATUS="$ROOT/platform/mt76/luci/modules/luci-base/htdocs/luci-static/resources/airui/apply_status_v2.js"
require_view_signal "$APPLY_STATUS" 'function run' 'setControlsBusy' 'function dataState' 'isRunning'

STATUS="$ROOT/platform/mt76/luci/modules/luci-mod-status/htdocs/luci-static/resources/view/status"
require_view_signal "$STATUS/airui_dashboard_v11.js" status-page-hero status-page-refresh status-page-updated
require_view_signal "$STATUS/airui_device_status_v10.js" status-page-hero status-page-refresh status-page-updated
require_view_signal "$STATUS/airui_device_statistics_v8.js" status-page-hero status-page-refresh status-page-updated
require_view_signal "$STATUS/airui_clients_v19.js" status-page-hero status-page-refresh status-page-updated

NETWORK="$ROOT/platform/mt76/luci/modules/luci-mod-network/htdocs/luci-static/resources/view/network"
require_view_signal "$NETWORK/airui_interfaces_v8.js" wireless-ref-head wireless-ref-toolbar air-refresh air-page-updated
require_view_signal "$NETWORK/airui_wireless_v13.js" wireless-ref-head wireless-ref-toolbar air-refresh air-page-updated

BASE="$ROOT/platform/mt76/luci/modules/luci-base/htdocs/luci-static/resources/view/airui"
require_view_signal "$BASE/settings_page_v12.js" air-settings-hero air-settings-page
require_view_signal "$BASE/settings_page_v2.js" air-settings-hero air-settings-page

SECURITY="$ROOT/platform/mt76/luci/modules/luci-app-airpro-security/htdocs/luci-static/resources/view/security"
require_view_signal "$SECURITY/airui_mac_filter_bulk.js" mac-filter-title mac-panel

echo "PASS: active AirUI views satisfy the shared theme component contract"

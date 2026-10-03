#!/bin/sh
# /usr/lib/aircnms/air_mode_helper.sh
# Shared mode and enrollment state helper for aircnms daemons

is_cloud_mode() {
    local mode
    mode="$(uci -q get aircnms.@aircnms[0].mode 2>/dev/null)"
    [ "$mode" = "cloud" ]
}

is_cloud_enrolled() {
    is_cloud_mode || return 1
    local dev_id
    dev_id="$(uci -q get aircnms.@aircnms[0].device_id 2>/dev/null)"
    [ -n "$dev_id" ] && [ "$dev_id" != "XXXXXXXXXX" ]
}

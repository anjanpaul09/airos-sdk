#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
css="$root/platform/mt76/luci/themes/luci-theme-airui/htdocs/luci-static/airui/reference.css"
a11y="$root/platform/mt76/luci/themes/luci-theme-airui/htdocs/luci-static/airui/accessibility.js"
dialog="$root/platform/mt76/luci/modules/luci-base/htdocs/luci-static/resources/airui/action_dialog.js"

require() {
	pattern="$1"
	file="$2"
	message="$3"
	if ! grep -Fq "$pattern" "$file"; then
		echo "FAIL: $message" >&2
		exit 1
	fi
}

require '@media (max-width: 1024px)' "$css" 'tablet breakpoint is missing'
require '@media (max-width: 680px)' "$css" 'mobile breakpoint is missing'
require ':focus-visible' "$css" 'keyboard focus styling is missing'
require 'min-height: 44px' "$css" 'mobile touch targets are missing'
require "aria-modal" "$a11y" 'modal semantics are missing'
require "event.key !== 'Tab'" "$a11y" 'modal focus trapping is missing'
require 'aria-live' "$dialog" 'progress announcements are missing'
require 'running[key]' "$dialog" 'duplicate action prevention is missing'

echo 'PASS: responsive, accessibility, confirmation, and progress contracts are present'

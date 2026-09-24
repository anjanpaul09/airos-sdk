#
# AirUI LuCI theme
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=AirUI Theme
LUCI_DEPENDS:=+luci-base
PKG_RELEASE:=2

PKG_LICENSE:=Apache-2.0

define Package/luci-theme-airui/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	uci -q delete luci.themes.AirUI
	uci commit luci
}
endef

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature

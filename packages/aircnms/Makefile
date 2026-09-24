include $(TOPDIR)/rules.mk
PKG_NAME:=aircnms
PKG_RELEASE:=3
PKG_SUBDIR:=$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -rf src/* $(PKG_BUILD_DIR)
	for d in $(BUILD_DIR)/hostapd-wpad-full-openssl/hostapd-*; do \
		[ -d "$$$$d" ] || continue; \
		cp "$$$$d/build/hostapd/src/utils/os_unix.o" $(STAGING_DIR)/usr/lib/ 2>/dev/null || true; \
		cp "$$$$d/build/hostapd/src/common/wpa_ctrl.o" $(STAGING_DIR)/usr/lib/ 2>/dev/null || true; \
		cp "$$$$d/src/common/wpa_ctrl.h" $(STAGING_DIR)/usr/include/ 2>/dev/null || true; \
	done
endef

AIRCNMS_DEPS += libnl libev hostapd jansson libmosquitto zlib libprotobuf-c libuci libcurl libubus libubox libjson-c libwebsockets-openssl libblobmsg-json libpcap tc-tiny kmod-sched-flower kmod-sched-act-police
AIRCNMS_DEPS := $(foreach X,$(AIRCNMS_DEPS),+$(X))

define Package/aircnms
	SECTION:=apps
	CATEGORY:=AirPro Applications
	TITLE:= aircnms
	DEPENDS:= $(AIRCNMS_DEPS)
endef

TARGET_EXTRACFLAGS += \
		      -I $(STAGING_DIR)/usr/include \
		      -I $(STAGING_DIR)/usr/include/libnl3 \
		      -I $(LINUX_DIR)/include \
		      -I $(STAGING_DIR)/target-$(BOARD)/include \
		      -L$(STAGING_DIR)/usr/lib

ifeq ($(CONFIG_TARGET_ipq), y)
	TARGET_BOARD_TYPE = BOARD_TYPE_QCA
else ifeq ($(CONFIG_TARGET_ramips), y)
	TARGET_BOARD_TYPE = BOARD_TYPE_MTK
	ifeq ($(CONFIG_TARGET_DEVICE_ramips_mt7621_DEVICE_mt7621-rfb-ax-nor), y)
		TARGET_BOARD_TYPE = BOARD_TYPE_MTK_JEDI
	endif
endif

MAKE_PACKAGE_ARGS += \
        EXTRA_CFLAGS='$(TARGET_CFLAGS)' \
        CCFLAGS="$(TARGET_CFLAGS)" \
        OFLAGS="$(TARGET_CFLAGS)" \
        REVISION="$(PKG_VERSION)" \
        BOARD_NAME="$(BOARD)" \
        BOARD_TYPE="$(TARGET_BOARD_TYPE)" \
        LOC_INCS="$(TARGET_EXTRACFLAGS)" \
        CC="$(TARGET_CC)" \
        NODEBUG=1 \
        UNAME="Linux" \
        INSTALL_PREFIX="$(PKG_INSTALL_DIR)" \
        STRIP="/bin/true" \
        UNIT_TEST_FLAG="$(UNIT_TEST_STATUS)"

define Build/Configure
endef

ifneq ($(DEVELOPER)$(CONFIG_PACKAGE_aircnms),)
	BUILD_LIBCOMMON:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/common $(MAKE_PACKAGE_ARGS)
	BUILD_LIBDHCPFP:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/dhcpfp $(MAKE_PACKAGE_ARGS)
	BUILD_LIBDS:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/ds $(MAKE_PACKAGE_ARGS)
	BUILD_LIBLOG:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/log $(MAKE_PACKAGE_ARGS)
	BUILD_LIBMOSQEV:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/mosqev $(MAKE_PACKAGE_ARGS)
	BUILD_LIBUNIXCOMM:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/unixcomm $(MAKE_PACKAGE_ARGS)

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK)
	BUILD_LIBNL80211:= $(MAKE) -C $(PKG_BUILD_DIR)/platform/mtk/nl80211 $(MAKE_PACKAGE_ARGS)
endif
	BUILD_MGRCGWD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/cgwd $(MAKE_PACKAGE_ARGS)
	BUILD_MGRNETSTATSD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/netstatsd $(MAKE_PACKAGE_ARGS)
	BUILD_MGRNETCONFD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/netconfd $(MAKE_PACKAGE_ARGS)
	BUILD_MGRCMDEXECD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/cmdexecd $(MAKE_PACKAGE_ARGS)
	BUILD_MGRSTAMOND:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/stamond $(MAKE_PACKAGE_ARGS)
	BUILD_MGR_ACLD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/acld $(MAKE_PACKAGE_ARGS)
	BUILD_MGR_EVENTD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/eventd $(MAKE_PACKAGE_ARGS)
	BUILD_MGR_AIRUID:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/airuid $(MAKE_PACKAGE_ARGS)
endif

define Build/Compile
	$(BUILD_LIBDHCPFP)
	$(CP) $(PKG_BUILD_DIR)/libs/dhcpfp/libdhcpfp.so.1.0.0 $(STAGING_DIR)/usr/lib
	rm -rf $(STAGING_DIR)/usr/lib/libdhcpfp.so
	( cd $(STAGING_DIR)/usr/lib/ ; ln -s libdhcpfp.so.1.0.0 libdhcpfp.so )

	$(BUILD_LIBCOMMON)
	$(CP) $(PKG_BUILD_DIR)/libs/common/libcommon.so.1.0.0 $(STAGING_DIR)/usr/lib
	rm -rf $(STAGING_DIR)/usr/lib/libcommon.so
	( cd $(STAGING_DIR)/usr/lib/ ; ln -s libcommon.so.1.0.0 libcommon.so )

	$(BUILD_LIBDS)
	$(CP) $(PKG_BUILD_DIR)/libs/ds/libds.so.1.0.0 $(STAGING_DIR)/usr/lib
	rm -rf $(STAGING_DIR)/usr/lib/libds.so
	( cd $(STAGING_DIR)/usr/lib/ ; ln -s libds.so.1.0.0 libds.so )

	$(BUILD_LIBLOG)
	$(CP) $(PKG_BUILD_DIR)/libs/log/liblog.so.1.0.0 $(STAGING_DIR)/usr/lib
	rm -rf $(STAGING_DIR)/usr/lib/liblog.so
	( cd $(STAGING_DIR)/usr/lib/ ; ln -s liblog.so.1.0.0 liblog.so )

	$(BUILD_LIBMOSQEV)
	$(CP) $(PKG_BUILD_DIR)/libs/mosqev/libmosqev.so.1.0.0 $(STAGING_DIR)/usr/lib
	rm -rf $(STAGING_DIR)/usr/lib/libmosqev.so
	( cd $(STAGING_DIR)/usr/lib/ ; ln -s libmosqev.so.1.0.0 libmosqev.so )

	$(BUILD_LIBUNIXCOMM)
	$(CP) $(PKG_BUILD_DIR)/libs/unixcomm/libunixcomm.so.1.0.0 $(STAGING_DIR)/usr/lib
	rm -rf $(STAGING_DIR)/usr/lib/libunixcomm.so
	( cd $(STAGING_DIR)/usr/lib/ ; ln -s libunixcomm.so.1.0.0 libunixcomm.so )

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK)
	$(BUILD_LIBNL80211)
	$(CP) $(PKG_BUILD_DIR)/platform/mtk/nl80211/libnl80211.so.1.0.0 $(STAGING_DIR)/usr/lib
	rm -rf $(STAGING_DIR)/usr/lib/libnl80211.so
	( cd $(STAGING_DIR)/usr/lib/ ; ln -s libnl80211.so.1.0.0 libnl80211.so )
endif

	$(BUILD_MGRCGWD)
	$(BUILD_MGRNETSTATSD)
	$(BUILD_MGRNETCONFD)
	$(BUILD_MGRCMDEXECD)
	$(BUILD_MGRSTAMOND)
	$(BUILD_MGR_ACLD)
	$(BUILD_MGR_EVENTD)
	$(BUILD_MGR_AIRUID)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)usr/include
endef

define Package/aircnms/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/airpro/captive_portals/templates
	$(INSTALL_DIR) $(1)/etc/airpro/captive_portals/instances
	$(INSTALL_DIR) $(1)/etc/chilli/www
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib

	$(INSTALL_BIN) ./files/aircgwd $(1)/etc/init.d
	$(INSTALL_BIN) ./files/airnetstatsd $(1)/etc/init.d
	$(INSTALL_BIN) ./files/airnetconfd $(1)/etc/init.d
	$(INSTALL_BIN) ./files/aircmdexecd $(1)/etc/init.d
	$(INSTALL_BIN) ./files/airstamond $(1)/etc/init.d
	$(INSTALL_BIN) ./files/aireventd $(1)/etc/init.d
	$(INSTALL_BIN) ./files/airuid $(1)/etc/init.d
	$(INSTALL_BIN) ./files/air_ssid_check.sh $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/air_led_state.sh $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/air_setmac_ssid.sh $(1)/usr/sbin/
	$(INSTALL_DATA) ./files/etc/airpro/captive_portals/templates/*.template $(1)/etc/airpro/captive_portals/templates/
	$(INSTALL_DATA) ./files/etc/chilli/www/radiusdesk.html $(1)/etc/chilli/www/

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK)
	$(INSTALL_BIN) ./files/airinit_mtk $(1)/etc/init.d/airinit
endif

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
	$(INSTALL_BIN) ./files/airinit_jedi $(1)/etc/init.d/airinit
endif
	$(CP) $(PKG_BUILD_DIR)/libs/dhcpfp/libdhcpfp.so.1.0.0 $(1)/usr/lib
	rm -rf $(1)/usr/lib/libdhcpfp.so
	( cd $(1)/usr/lib/ ; ln -s libdhcpfp.so.1.0.0 libdhcpfp.so )

	$(CP) $(PKG_BUILD_DIR)/libs/common/libcommon.so.1.0.0 $(1)/usr/lib
	rm -rf $(1)/usr/lib/libcommon.so
	( cd $(1)/usr/lib/ ; ln -s libcommon.so.1.0.0 libcommon.so )

	$(CP) $(PKG_BUILD_DIR)/libs/ds/libds.so.1.0.0 $(1)/usr/lib
	rm -rf $(1)/usr/lib/libds.so
	( cd $(1)/usr/lib/ ; ln -s libds.so.1.0.0 libds.so )

	$(CP) $(PKG_BUILD_DIR)/libs/log/liblog.so.1.0.0 $(1)/usr/lib
	rm -rf $(1)/usr/lib/liblog.so
	( cd $(1)/usr/lib/ ; ln -s liblog.so.1.0.0 liblog.so )

	$(CP) $(PKG_BUILD_DIR)/libs/mosqev/libmosqev.so.1.0.0 $(1)/usr/lib
	rm -rf $(1)/usr/lib/libmosqev.so
	( cd $(1)/usr/lib/ ; ln -s libmosqev.so.1.0.0 libmosqev.so )

	$(CP) $(PKG_BUILD_DIR)/libs/unixcomm/libunixcomm.so.1.0.0 $(1)/usr/lib
	rm -rf $(1)/usr/lib/libunixcomm.so
	( cd $(1)/usr/lib/ ; ln -s libunixcomm.so.1.0.0 libunixcomm.so )

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK)
	$(CP) $(PKG_BUILD_DIR)/platform/mtk/nl80211/libnl80211.so.1.0.0 $(1)/usr/lib/
	rm -rf $(1)/usr/lib/libnl80211.so
	( cd $(1)/usr/lib ; ln -s libnl80211.so.1.0.0 libnl80211.so )
endif

	$(CP) $(PKG_BUILD_DIR)/managers/cgwd/cgwd $(1)/usr/sbin/air-cgwd
	$(CP) $(PKG_BUILD_DIR)/managers/netstatsd/netstatsd $(1)/usr/sbin/air-netstatsd
	$(CP) $(PKG_BUILD_DIR)/managers/netconfd/netconfd $(1)/usr/sbin/air-netconfd
	$(CP) $(PKG_BUILD_DIR)/managers/cmdexecd/cmdexecd $(1)/usr/sbin/air-cmdexecd
	$(CP) $(PKG_BUILD_DIR)/managers/stamond/stamond $(1)/usr/sbin/air-stamond
	$(CP) $(PKG_BUILD_DIR)/managers/acld/acld $(1)/usr/sbin/air-acld
	$(CP) $(PKG_BUILD_DIR)/managers/eventd/eventd $(1)/usr/sbin/air-eventd
	$(CP) $(PKG_BUILD_DIR)/managers/airuid/airuid $(1)/usr/sbin/airuid

endef

$(eval $(call BuildPackage,aircnms))

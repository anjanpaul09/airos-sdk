include $(TOPDIR)/rules.mk
PKG_NAME:=aircnms
PKG_RELEASE:=1
PKG_SUBDIR:=$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -rf src/* $(PKG_BUILD_DIR)
	#cp $(BUILD_DIR)/hostapd-wpad-full-openssl/hostapd-*/build/hostapd/src/utils/os_unix.o $(STAGING_DIR)/usr/lib/
	#cp $(BUILD_DIR)/hostapd-wpad-full-openssl/hostapd-*/build/hostapd/src/common/wpa_ctrl.o $(STAGING_DIR)/usr/lib/
	#cp $(BUILD_DIR)/hostapd-wpad-full-openssl/hostapd-*/src/common/wpa_ctrl.h $(STAGING_DIR)/usr/include/
endef
AIRCNMS_DEPS += libnl libev jansson libmosquitto zlib libprotobuf-c libuci libcurl kmod-airdpi libubus libubox libjson-c libwebsockets-openssl +libblobmsg-json
AIRCNMS_DEPS := $(foreach X,$(AIRCNMS_DEPS),+$(X))

define Package/aircnms
	SECTION:=apps
	CATEGORY:=AirPro Applications
	TITLE:= aircnms
	DEPENDS:= $(AIRCNMS_DEPS) 
endef

TARGET_EXTRACFLAGS += \
		      -I $(STAGING_DIR)/usr/include \
		      -I $(STAGING_DIR)/usr/include/airdpi \
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

#UNIT_TEST_STATUS = UNIT_TEST_DISABLE 
#UNIT_TEST_STATUS = UNIT_TEST_ENABLE

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
	BUILD_LIBDS:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/ds $(MAKE_PACKAGE_ARGS)
	BUILD_LIBLOG:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/log $(MAKE_PACKAGE_ARGS)
	BUILD_LIBMOSQEV:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/mosqev $(MAKE_PACKAGE_ARGS)
	BUILD_LIBUNIXCOMM:= $(MAKE) -C $(PKG_BUILD_DIR)/libs/unixcomm $(MAKE_PACKAGE_ARGS)
	# ############################## LIB ENDS #######################################

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK)
	BUILD_LIBNL80211:= $(MAKE) -C $(PKG_BUILD_DIR)/platform/mtk/nl80211 $(MAKE_PACKAGE_ARGS)
endif
	BUILD_MGRCGWD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/cgwd $(MAKE_PACKAGE_ARGS)
	BUILD_MGRNETSTATSD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/netstatsd $(MAKE_PACKAGE_ARGS)
	BUILD_MGRNETCONFD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/netconfd $(MAKE_PACKAGE_ARGS)
	BUILD_MGRCMDEXECD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/cmdexecd $(MAKE_PACKAGE_ARGS)
	BUILD_MGRNETEVD:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/netevd $(MAKE_PACKAGE_ARGS)
	BUILD_AIRCLI:= $(MAKE) -C $(PKG_BUILD_DIR)/tools/airubusd $(MAKE_PACKAGE_ARGS)
endif

define Build/Compile
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
	
	#$(BUILD_LIBUBUSIPC)
	#$(CP) $(PKG_BUILD_DIR)/libs/ubus-ipc/libubus-ipc.so.1.0.0 $(STAGING_DIR)/usr/lib
	#rm -rf $(STAGING_DIR)/usr/lib/libubus-ipc.so
	#( cd $(STAGING_DIR)/usr/lib/ ; ln -s libubus-ipc.so.1.0.0 libubus-ipc.so )

	#$(BUILD_LIBUBUSIPC_EXAMPLES)

	#$(BUILD_LIBDATAPIPELINE)
	#$(CP) $(PKG_BUILD_DIR)/libs/datapipeline/libdatapipeline.so.1.0.0 $(STAGING_DIR)/usr/lib
	#rm -rf $(STAGING_DIR)/usr/lib/libdatapipeline.so
	#( cd $(STAGING_DIR)/usr/lib/ ; ln -s libdatapipeline.so.1.0.0 libdatapipeline.so )
	
	#$(BUILD_LIBUCICONFIG)
	#$(CP) $(PKG_BUILD_DIR)/libs/uciconfig/libuciconfig.so.1.0.0 $(STAGING_DIR)/usr/lib
	#rm -rf $(STAGING_DIR)/usr/lib/libuciconfig.so
	#( cd $(STAGING_DIR)/usr/lib/ ; ln -s libuciconfig.so.1.0.0 libuciconfig.so )

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
	$(BUILD_MGRNETEVD)
	$(BUILD_AIRCLI)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)usr/include
endef

define Package/aircnms/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib

	$(INSTALL_BIN) ./files/air_cgwdinit $(1)/etc/init.d
	$(INSTALL_BIN) ./files/air_netstatsdinit $(1)/etc/init.d
	$(INSTALL_BIN) ./files/air_netconfdinit $(1)/etc/init.d
	$(INSTALL_BIN) ./files/air_cmdexecdinit $(1)/etc/init.d
	$(INSTALL_BIN) ./files/air_netevdinit $(1)/etc/init.d

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK)
	$(INSTALL_BIN) ./files/airinit_mtk $(1)/etc/init.d/airinit
endif

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
	$(INSTALL_BIN) ./files/airinit_jedi $(1)/etc/init.d/airinit
endif
	$(INSTALL_BIN) ./files/airinit_logger $(1)/etc/init.d/airinit_logger

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

	#$(CP) $(PKG_BUILD_DIR)/libs/datapipeline/libdatapipeline.so.1.0.0 $(1)/usr/lib
	#rm -rf $(1)/usr/lib/libdatapipeline.so
	#( cd $(1)/usr/lib/ ; ln -s libdatapipeline.so.1.0.0 libdatapipeline.so )

	#$(CP) $(PKG_BUILD_DIR)/libs/uciconfig/libuciconfig.so.1.0.0 $(1)/usr/lib
	#rm -rf $(1)/usr/lib/libuciconfig.so
	#( cd $(1)/usr/lib/ ; ln -s libuciconfig.so.1.0.0 libuciconfig.so )

ifeq ($(TARGET_BOARD_TYPE), BOARD_TYPE_MTK)
	$(CP) $(PKG_BUILD_DIR)/platform/mtk/nl80211/libnl80211.so.1.0.0 $(1)/usr/lib/
	rm -rf $(1)/usr/lib/libnl80211.so
	( cd $(1)/usr/lib ; ln -s libnl80211.so.1.0.0 libnl80211.so )
endif

	#$(CP) $(PKG_BUILD_DIR)/libs/ubus-ipc/libubus-ipc.so.1.0.0 $(1)/usr/lib
	#rm -rf $(1)/usr/lib/libubus-ipc.so
	#( cd $(1)/usr/lib/ ; ln -s libubus-ipc.so.1.0.0 libubus-ipc.so )

	$(CP) $(PKG_BUILD_DIR)/managers/cgwd/cgwd $(1)/usr/sbin/air-cgwd
	$(CP) $(PKG_BUILD_DIR)/managers/netstatsd/netstatsd $(1)/usr/sbin/air-netstatsd
	$(CP) $(PKG_BUILD_DIR)/managers/netconfd/netconfd $(1)/usr/sbin/air-netconfd
	$(CP) $(PKG_BUILD_DIR)/managers/cmdexecd/cmdexecd $(1)/usr/sbin/air-cmdexecd
	$(CP) $(PKG_BUILD_DIR)/managers/netevd/netevd $(1)/usr/sbin/air-netevd
	$(CP) $(PKG_BUILD_DIR)/tools/airubusd/airubusd $(1)/usr/sbin

endef

$(eval $(call BuildPackage,aircnms))


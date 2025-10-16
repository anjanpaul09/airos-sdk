include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=airdpi
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define KernelPackage/airdpi
	SUBMENU:=Filesystems
	TITLE:=DPI Kernel driver
	FILES:=$(PKG_BUILD_DIR)/adpi/adpi.ko
	AUTOLOAD:=$(call AutoLoad,30,adpi,1)
endef

define KernelPackage/airdpi/description
	Kernel module for AirPro DPI
endef

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	M="$(PKG_BUILD_DIR)/adpi"

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
	$(MAKE_OPTS) \
	modules
	# mv $(PKG_BUILD_DIR)/adpi/Module.symvers /home/user/projects/airpro/MTK/ax820/23/openwrt/build_dir/target-mipsel_24kc_musl/linux-ramips_mt7621/airdpi/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include/airdpi
	$(CP) $(PKG_BUILD_DIR)/adpi/air_ioctl.h $(STAGING_DIR)/usr/include/airdpi
	# $(CP) $(PKG_BUILD_DIR)/adpi/air_common.h $(STAGING_DIR)/usr/include/airdpi
	$(CP) $(PKG_BUILD_DIR)/adpi/air_coplane.h $(STAGING_DIR)/usr/include/airdpi
endef

$(eval $(call KernelPackage,airdpi))


###############################################################################
#
# QCA unit override for target library
#
###############################################################################

# Common target library sources
UNIT_SRC := $(TARGET_COMMON_SRC)

# Platform specific target library sources
UNIT_SRC_PLATFORM := $(OVERRIDE_DIR)
ifeq ($(CONFIG_PLATFORM_QCA_QSDK110),y)
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_ioctl_stats_11ax.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_qca_11ax.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/wiphy_info_11ax.c
else
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_ioctl_stats.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_qca.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/wiphy_info.c
endif

UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_init.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_switch.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/hostapd_util.c
UNIT_SRC_TOP += $(OVERRIDE_DIR)/ssdk_util.c


UNIT_CFLAGS += -I$(OVERRIDE_DIR)
UNIT_CFLAGS += -I$(OVERRIDE_DIR)/inc

ifeq ($(CONFIG_PLATFORM_QCA_QSDK110),y)
UNIT_LDFLAGS += -lqca_tools
UNIT_LDFLAGS += -lqca_nl80211_wrapper
UNIT_LDFLAGS += -lnl-3
UNIT_LDFLAGS += -lnl-genl-3
endif

UNIT_DEPS += $(PLATFORM_DIR)/src/lib/ioctl80211

UNIT_DEPS += $(PLATFORM_DIR)/src/lib/bsal
UNIT_DEPS += src/lib/hostap
UNIT_DEPS_CFLAGS += src/lib/crt
UNIT_DEPS_CFLAGS += src/lib/json_util
UNIT_DEPS_CFLAGS += src/lib/ovsdb
UNIT_DEPS_CFLAGS += src/lib/daemon

UNIT_EXPORT_CFLAGS := -I$(UNIT_PATH)
UNIT_EXPORT_LDFLAGS += $(SDK_LIB_DIR) -lm $(UNIT_LDFLAGS)

STAGING_USR_LIB ?= $(STAGING_DIR)/usr/lib

$(UNIT_BUILD)/os_unix.o: $(STAGING_USR_LIB)/os_unix.o
	cp $< $@

$(UNIT_BUILD)/wpa_ctrl.o: $(STAGING_USR_LIB)/wpa_ctrl.o
	cp $< $@

UNIT_OBJ += $(UNIT_BUILD)/os_unix.o
UNIT_OBJ += $(UNIT_BUILD)/wpa_ctrl.o

UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)

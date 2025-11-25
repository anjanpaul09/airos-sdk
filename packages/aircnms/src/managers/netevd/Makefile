UNIT_SRC += src/main.c
UNIT_SRC += src/nlev.c
UNIT_SRC += src/nl.c
UNIT_SRC += src/hostapd_ev.c
UNIT_SRC += src/wpa_os_shim.c
UNIT_SRC += src/netev_info_events.c
UNIT_SRC += src/netev_ubus_tx.c
UNIT_SRC += src/netev_client_events.c
UNIT_SRC += src/netev_vif_info.c
UNIT_SRC += src/netev_device_info.c
UNIT_SRC += src/netev_client_cap.c

# Platform target code for VIF info
ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_SRC += ../../platform/mtk/target/target_nl80211_init.c
UNIT_SRC += ../../platform/mtk/target/target_stats.c
UNIT_SRC += ../../platform/mtk/target/target_ethstats.c
#UNIT_SRC += ../../platform/mtk/target/target_dhcp.c
UNIT_SRC += ../../platform/mtk/target/wiphy_info.c
UNIT_SRC += ../../platform/mtk/nl80211/src/nl80211_vif_stats.c
endif

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -Isrc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/dhcpfp/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -Wall -Werror
UNIT_CFLAGS += -I$(STAGING_DIR)/usr/include

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_CFLAGS += -I../../platform/mtk/nl80211/inc
UNIT_CFLAGS += -I../../platform/mtk/target
UNIT_CFLAGS += -DCONFIG_PLATFORM_MTK
endif


UNIT_LDFLAGS := -lpthread
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lnl-3 -lnl-genl-3
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lds
UNIT_LDFLAGS += -ldhcpfp
UNIT_LDFLAGS += $(STAGING_DIR)/usr/lib/wpa_ctrl.o 
TARGET_EXTRACFLAGS += -I $(STAGING_DIR)/usr/include/libnl3

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_LDFLAGS += -lnl80211
endif

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(TARGET_EXTRACFLAGS) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o netevd
clean:
	rm -rf netevd


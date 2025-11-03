UNIT_SRC += src/main.c
UNIT_SRC += src/netstats_device_report.c
UNIT_SRC += src/netstats_vif_report.c
UNIT_SRC += src/netstats_client_report.c
UNIT_SRC += src/netstats_neighbor_report.c
UNIT_SRC += src/netstats_initiate.c
UNIT_SRC += src/netstats_prepare_stats.c
UNIT_SRC += src/netstats_process_stats.c 
UNIT_SRC += src/netstats_common.c 
UNIT_SRC += src/netstats_queue.c
UNIT_SRC += src/netstats_ubus.c

UNIT_SRC += ../../platform/common/target_device.c


ifeq ($(BOARD_TYPE), BOARD_TYPE_QCA)
UNIT_SRC += ../../platform/qca/target/target_init.c
UNIT_SRC += ../../platform/qca/ioctl80211/ioctl80211.c
UNIT_SRC += ../../platform/qca/ioctl80211/ioctl80211_radio.c
UNIT_SRC += ../../platform/qca/ioctl80211/ioctl80211_vif.c
UNIT_SRC += ../../platform/qca/ioctl80211/ioctl80211_client.c
UNIT_SRC += ../../platform/qca/ioctl80211/ioctl80211_survey.c
UNIT_SRC += ../../platform/qca/ioctl80211/ioctl80211_scan.c
UNIT_SRC += ../../platform/qca/ioctl80211/ioctl80211_device.c
UNIT_SRC += ../../platform/qca/target/target_ioctl_stats.c
endif

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
UNIT_SRC += src/sm_jedi_nl_event.c
UNIT_SRC += src/sm_checkwifi.c
UNIT_SRC += ../../platform/mtk_jedi/target/target_init.c
UNIT_SRC += ../../platform/mtk_jedi/target/target_stats.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi_vif.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi_client.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi_scan.c
endif

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_SRC += src/netstats_nl_event.c
UNIT_SRC += ../../platform/mtk/target/target_nl80211_init.c
UNIT_SRC += ../../platform/mtk/target/target_stats.c
UNIT_SRC += ../../platform/mtk/target/wiphy_info.c
endif


UNIT_CFLAGS += -I../../libs/unixcomm/inc
UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -Isrc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/unixcomm/inc
UNIT_CFLAGS += -I../../../../airdpi/src/adpi
UNIT_CFLAGS += -Wall -Werror 


ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
UNIT_CFLAGS += -I../../platform/mtk_jedi/ioctljedi/inc
UNIT_CFLAGS += -I../../platform/mtk_jedi/target
UNIT_CFLAGS += -DCONFIG_PLATFORM_MTK_JEDI
endif

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_CFLAGS += -I../../platform/mtk/nl80211/inc
UNIT_CFLAGS += -DCONFIG_PLATFORM_MTK
endif

ifeq ($(BOARD_TYPE), BOARD_TYPE_QCA)
UNIT_CFLAGS += -I../../platform/qca/ioctl80211/inc
UNIT_CFLAGS += -DCONFIG_PLATFORM_QCA_QSDK110
UNIT_CFLAGS += -DCONFIG_PLATFORM_QCA
endif


UNIT_LDFLAGS := -lpthread
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -ldl
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lz
UNIT_LDFLAGS += -lds
UNIT_LDFLAGS += -lunixcomm
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_LDFLAGS += -lnl80211
endif

CFLAGS := $(UNIT_CFLAGS) 
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o netstatsd
clean:
	rm -rf sm

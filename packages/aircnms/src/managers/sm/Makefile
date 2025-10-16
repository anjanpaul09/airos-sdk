UNIT_SRC += src/main.c
UNIT_SRC += src/sm_qm.c
UNIT_SRC += src/sm_client_report.c
UNIT_SRC += src/sm_neighbor_report.c
UNIT_SRC += src/sm_monitor.c
UNIT_SRC += src/sm_common.c
UNIT_SRC += src/sm_device_report.c
UNIT_SRC += src/sm_prepare_stats.c
UNIT_SRC += src/sm_vif_stats.c 
#UNIT_SRC += src/get_dummy_vif.c 
UNIT_SRC += src/sm_rx_event.c
UNIT_SRC += src/sm_msgrx.c
UNIT_SRC += src/sm_queue.c
UNIT_SRC += src/sm_unixcomm_server.c
## Remove legacy conn layers; use libunixcomm
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
UNIT_SRC += src/sm_nl_event.c
UNIT_SRC += ../../platform/mtk/target/target_nl80211_init.c
UNIT_SRC += ../../platform/mtk/target/target_stats.c
UNIT_SRC += ../../platform/mtk/target/wiphy_info.c
endif


UNIT_CFLAGS += -I../../libs/unixcomm/inc
UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/datapipeline/inc
UNIT_CFLAGS += -I../../libs/unixcomm/inc
UNIT_CFLAGS += -I../../../../airdpi/src/adpi
#UNIT_CFLAGS += -Wall 


ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
UNIT_CFLAGS += -I../../platform/mtk_jedi/ioctljedi/inc
UNIT_CFLAGS += -I../../platform/mtk_jedi/target
UNIT_CFLAGS += -DCONFIG_PLATFORM_MTK_JEDI
endif

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_CFLAGS += -I../../platform/mtk/nl80211/inc
#UNIT_CFLAGS += -I../../platform/mtk/target
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

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_LDFLAGS += -lnl80211
#UNIT_LDFLAGS += -lnl-3
#UNIT_LDFLAGS += -lnl-genl-3
endif

CFLAGS := $(UNIT_CFLAGS) 
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o sm
clean:
	rm -rf sm

UNIT_SRC += src/main.c
UNIT_SRC += src/sm_qm.c
UNIT_SRC += src/genmsg.c
UNIT_SRC += src/dpp_get_client.c
UNIT_SRC += src/dpp_get_vif.c
UNIT_SRC += src/dpp_get_device.c
#UNIT_SRC += src/sm_client_report.c
#UNIT_SRC += src/sm_rssi_report.c
UNIT_SRC += src/sm_common.c

UNIT_SRC += ../../managers/qm/qm_conn/src/qm_conn.c
#UNIT_SRC += ../../platform/mtk/target/target_nl80211_init.c
#UNIT_SRC += ../../platform/mtk/target/target_stats.c

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
UNIT_SRC += ../../platform/mtk_jedi/target/target_init.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi.c
UNIT_SRC += ../../platform/mtk_jedi/target/target_client.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi_vif.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi_client.c
UNIT_SRC += ../../platform/mtk_jedi/target/target_stats.c
endif

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
#UNIT_CFLAGS += -I../../libs/osa/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/datapipeline/inc
UNIT_CFLAGS += -I../../libs/const/inc
UNIT_CFLAGS += -Ism_conn/src/
UNIT_CFLAGS += -I../../platform/mtk/nl80211/inc

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
UNIT_CFLAGS += -I../../platform/mtk_jedi/ioctljedi/inc
UNIT_CFLAGS += -I../../platform/mtk_jedi/target
UNIT_CFLAGS += -DCONFIG_PLATFORM_MTK_JEDI
endif

UNIT_CFLAGS += -I../../managers/qm/qm_conn/src

UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -ldl
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
#UNIT_LDFLAGS += -losa
UNIT_LDFLAGS += -lds
UNIT_LDFLAGS += -ldatapipeline
#UNIT_LDFLAGS += -lconst
#UNIT_LDFLAGS += -lnl80211
UNIT_CFLAGS += -DCONFIG_PLATFORM_MTK

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o testqm
clean:
	rm -rf testqm

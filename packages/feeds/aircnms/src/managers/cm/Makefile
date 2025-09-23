UNIT_SRC += src/main.c
UNIT_SRC += src/cm_event.c
UNIT_SRC += src/cm_queue.c
UNIT_SRC += src/cm_process_msg.c
UNIT_SRC += src/cm_set_process.c 
UNIT_SRC += src/cm_network.c 
UNIT_SRC += src/cm_vlan.c 
UNIT_SRC += src/cm_nat.c
UNIT_SRC += src/target_config.c
UNIT_SRC += src/cm_qm.c
UNIT_SRC += src/cm_rate_limit.c
UNIT_SRC += src/cm_checkwifi.c 
UNIT_SRC += src/cm_captive_portal.c 
UNIT_SRC += src/uci_config/uci_ops.c
UNIT_SRC += src/uci_config/uci_wireless.c
UNIT_SRC += cm_conn/src/cm_conn.c
UNIT_SRC += ../../managers/qm/qm_conn/src/qm_conn.c

UNIT_SRC += src/cm_test_set.c
ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_SRC += src/acl.c
UNIT_SRC += ../../platform/mtk/target/target_nl80211_init.c
endif

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
UNIT_SRC += src/cm_jedi_acl.c 
UNIT_SRC += ../../platform/mtk_jedi/target/target_init.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi_vif.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi_client.c
UNIT_SRC += ../../platform/mtk_jedi/target/target_stats.c
UNIT_SRC += ../../platform/mtk_jedi/ioctljedi/ioctljedi_scan.c
UNIT_SRC += src/target_jedi.c
endif

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK_JEDI)
UNIT_CFLAGS += -I../../platform/mtk_jedi/ioctljedi/inc
UNIT_CFLAGS += -I../../platform/mtk_jedi/target
UNIT_CFLAGS += -DCONFIG_PLATFORM_MTK_JEDI
endif

ifeq ($(BOARD_TYPE), BOARD_TYPE_MTK)
UNIT_CFLAGS += -DCONFIG_PLATFORM_MTK
UNIT_LDFLAGS += -lnl-3
UNIT_LDFLAGS += -lnl-genl-3
UNIT_LDFLAGS += -lnl80211
endif

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../qm/src/
UNIT_CFLAGS += -Isrc/uci_config/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/mosqev/inc
UNIT_CFLAGS += -Icm_conn/src/
UNIT_CFLAGS += -I../../managers/qm/qm_conn/src
UNIT_CFLAGS += -I../../platform/mtk/nl80211/inc
UNIT_CFLAGS += -I../../libs/datapipeline/inc
UNIT_CFLAGS += -I../../../../airdpi/src/adpi
#UNIT_CFLAGS += -Wall 

UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lcurl
UNIT_LDFLAGS += -ldl
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lds
UNIT_LDFLAGS += -lz
UNIT_LDFLAGS += -lmosquitto
UNIT_LDFLAGS += -lmosqev
UNIT_LDFLAGS += -lprotobuf-c
UNIT_LDFLAGS += -luci
UNIT_LDFLAGS += -lubox
#UNIT_LDFLAGS += -lnl80211
UNIT_LDFLAGS += -lnl-3
UNIT_LDFLAGS += -lnl-genl-3

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o cm
clean:
	rm -rf cm

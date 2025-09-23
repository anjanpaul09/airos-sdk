UNIT_SRC += src/main.c
UNIT_SRC += src/qm_mqtt.c
UNIT_SRC += src/qm_event.c
UNIT_SRC += src/qm_queue.c
UNIT_SRC += qm_conn/src/qm_conn.c
UNIT_SRC += src/msgrx.c 
#UNIT_SRC += src/qm_json.c 
UNIT_SRC += src/qm_newjson.c 
#UNIT_SRC += src/qm_log.c
UNIT_SRC += src/qm_air.c 
UNIT_SRC += src/qm_decrypt.c 
UNIT_SRC += src/qm_server_req.c 
UNIT_SRC += ../../managers/cm/cm_conn/src/cm_conn.c
UNIT_SRC += ../../managers/sm/sm_conn/src/sm_conn.c
UNIT_SRC += ../../managers/dm/dm_conn/src/dm_conn.c

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/mosqev/inc
UNIT_CFLAGS += -Iqm_conn/src/
UNIT_CFLAGS += -I../../managers/cm/cm_conn/src
UNIT_CFLAGS += -I../../managers/sm/sm_conn/src
UNIT_CFLAGS += -I../../managers/dm/dm_conn/src
#UNIT_CFLAGS += -Wall

UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -ldl
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lds
UNIT_LDFLAGS += -lz
UNIT_LDFLAGS += -lmosqev
UNIT_LDFLAGS += -lmosquitto
UNIT_LDFLAGS += -lcurl
UNIT_LDFLAGS += -lcrypto
UNIT_LDFLAGS += -lssl

ifeq ($(UNIT_TEST_FLAG), UNIT_TEST_ENABLE)
UNIT_CFLAGS += -DCONFIG_UNIT_TEST_ENABLE
endif

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o qm
clean:
	rm -rf qm

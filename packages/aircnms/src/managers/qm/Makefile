UNIT_SRC += src/main.c
UNIT_SRC += src/qm_mqtt.c
UNIT_SRC += src/qm_queue.c
UNIT_SRC += src/msgrx.c 
#UNIT_SRC += src/qm_json.c 
UNIT_SRC += src/qm_newjson.c 
#UNIT_SRC += src/qm_log.c
UNIT_SRC += src/qm_air.c 
UNIT_SRC += src/qm_decrypt.c 
UNIT_SRC += src/qm_server_req.c 

UNIT_SRC += src/qm_unixcomm_server.c


#UNIT_SRC_MOCK += src/mock/qm_mock.c
#UNIT_SRC_MOCK += qm_conn/src/qm_conn.c

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/mosqev/inc
UNIT_CFLAGS += -I../../libs/unixcomm/inc
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
UNIT_LDFLAGS += -lunixcomm
UNIT_LDFLAGS += -lpthread

ifeq ($(UNIT_TEST_FLAG), UNIT_TEST_ENABLE)
UNIT_CFLAGS += -DCONFIG_UNIT_TEST_ENABLE
endif

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o qm
#	$(CC) $(UNIT_SRC_MOCK) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o qm_mock
clean:
	rm -rf qm

UNIT_SRC += src/main.c
UNIT_SRC += src/cgw_init.c
UNIT_SRC += src/cgw_ubus.c
UNIT_SRC += src/cgw_queue.c
UNIT_SRC += src/cgw_state_mgr.c
UNIT_SRC += src/cgw_ws.c
UNIT_SRC += src/cgw_mqtt.c
UNIT_SRC += src/cgw_cloud_reg.c
UNIT_SRC += src/cgw_decrypt.c
UNIT_SRC += src/cgw_msgrx.c
UNIT_SRC += src/cgw_json.c
UNIT_SRC += src/cgw_ubus_tx.c


UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -Isrc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/mosqev/inc
UNIT_CFLAGS += -I../../libs/unixcomm/inc
UNIT_CFLAGS += -Wall -Werror

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
UNIT_LDFLAGS += -lwebsockets
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json

ifeq ($(UNIT_TEST_FLAG), UNIT_TEST_ENABLE)
UNIT_CFLAGS += -DCONFIG_UNIT_TEST_ENABLE
endif

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o cgwd
clean:
	rm -rf cgwd

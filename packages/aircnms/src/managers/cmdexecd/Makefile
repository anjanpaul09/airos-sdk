UNIT_SRC += src/main.c
UNIT_SRC += src/cmdexec_cgw.c
UNIT_SRC += src/cmdexec_process_msg.c 
UNIT_SRC += src/cmdexec_queue.c
UNIT_SRC += src/cmdexec_handle_cmd.c
UNIT_SRC += src/cmdexec_target.c
UNIT_SRC += src/cmdexec_upgrade.c
UNIT_SRC += src/cmdexec_ubus_rx.c
UNIT_SRC += src/cmdexec_ubus_tx.c

## Remove legacy conn layers; use libunixcomm


UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/datapipeline/inc

UNIT_CFLAGS += -I../../libs/unixcomm/inc
UNIT_CFLAGS += -Wall -Werror

UNIT_LDFLAGS := -lpthread
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lcurl
UNIT_LDFLAGS += -ldl
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lds
UNIT_LDFLAGS += -lunixcomm
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json


CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o cmdexecd
clean:
	rm -rf cmdexecd


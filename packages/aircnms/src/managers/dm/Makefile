UNIT_SRC += src/main.c
UNIT_SRC += src/dm_qm.c
UNIT_SRC += src/dm_alarm.c
UNIT_SRC += src/dm_monitor.c
UNIT_SRC += src/dm_process_msg.c 
UNIT_SRC += src/dm_event.c
UNIT_SRC += src/dm_queue.c
UNIT_SRC += src/dm_handle_cmd.c
UNIT_SRC += src/dm_target.c
UNIT_SRC += src/dm_upgrade.c
UNIT_SRC += src/dm_unixcomm_server.c

## Remove legacy conn layers; use libunixcomm


UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../pbuf/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/datapipeline/inc

UNIT_CFLAGS += -I../../libs/unixcomm/inc


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


CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o dm
clean:
	rm -rf dm


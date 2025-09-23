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

UNIT_SRC += dm_conn/src/dm_conn.c
UNIT_SRC += ../../managers/qm/qm_conn/src/qm_conn.c


UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Idm_conn/src/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../pbuf/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/datapipeline/inc

UNIT_CFLAGS += -I../../managers/qm/qm_conn/src


UNIT_LDFLAGS := -lpthread
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lcurl
UNIT_LDFLAGS += -ldl
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lds


CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o dm
clean:
	rm -rf dm


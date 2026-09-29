UNIT_SRC += src/main.c
UNIT_SRC += src/onbd_state.c
UNIT_SRC += src/onbd_persist.c
UNIT_SRC += src/onbd_observe.c
UNIT_SRC += src/onbd_probe.c
UNIT_SRC += src/onbd_recovery.c
UNIT_SRC += src/onbd_ubus.c

UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -Wall -Wextra -Werror

UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcurl
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -luci
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o onbd

clean:
	rm -f onbd

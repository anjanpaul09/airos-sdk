UNIT_SRC += src/main.c
UNIT_SRC += src/eventd_ubus_alarm.c

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/eventd/inc
UNIT_CFLAGS += -Wall -Werror

UNIT_LDFLAGS := -lpthread
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -leventd
UNIT_LDFLAGS += -lubus -lubox
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lds
# Satisfy libeventd.so refs to blobmsg_format_json (--as-needed drops -lblobmsg_json otherwise)
UNIT_LDFLAGS += -Wl,--no-as-needed -lblobmsg_json -Wl,--as-needed

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o eventd
clean:
	rm -rf eventd

UNIT_SRC += src/main.c
UNIT_SRC += src/airui_ubus.c
UNIT_SRC += src/airui_response.c
UNIT_SRC += src/airui_apply_status.c
UNIT_SRC += src/airui_ubus_client.c
UNIT_SRC += src/airui_network.c
UNIT_SRC += src/airui_interface.c
UNIT_SRC += src/airui_status.c
UNIT_SRC += src/airui_mode.c
UNIT_SRC += src/airui_management.c
UNIT_SRC += src/airui_security.c
UNIT_SRC += src/airui_maintenance.c

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -I../../libs/common/inc
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -Wall -Werror

UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lnl-3
UNIT_LDFLAGS += -lnl-genl-3
UNIT_LDFLAGS += -lubus
UNIT_LDFLAGS += -lubox
UNIT_LDFLAGS += -ljson-c
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lblobmsg_json
UNIT_LDFLAGS += -luci

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o airuid

clean:
	rm -rf airuid

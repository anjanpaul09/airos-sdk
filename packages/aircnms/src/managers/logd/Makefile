UNIT_SRC += src/main.c
UNIT_SRC += src/logd_config.c
UNIT_SRC += src/logd_filter.c
UNIT_SRC += src/logd_rotate.c
UNIT_SRC += src/logd_stream.c
UNIT_SRC += src/logd_ubus.c

UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -Wall -Wextra -Werror

UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -luci
UNIT_LDFLAGS += -lubus -lubox -lblobmsg_json

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o logd

clean:
	rm -f logd

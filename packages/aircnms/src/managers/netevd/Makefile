UNIT_SRC += src/main.c
UNIT_SRC += src/nlev.c
UNIT_SRC += src/nl.c

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc

UNIT_CFLAGS += -Wall -Werror

UNIT_LDFLAGS := -lpthread
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lnl -lnl-genl-3 -lnl-3
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json

TARGET_EXTRACFLAGS += -I $(STAGING_DIR)/usr/include/libnl3

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(TARGET_EXTRACFLAGS) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o netevd
clean:
	rm -rf netevd


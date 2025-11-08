UNIT_SRC += src/main.c
UNIT_SRC += src/nlev.c
UNIT_SRC += src/nl.c
UNIT_SRC += src/hostapd_ev.c
UNIT_SRC += src/wpa_os_shim.c

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
UNIT_CFLAGS += -Wall -Werror
UNIT_CFLAGS += -I$(STAGING_DIR)/usr/include


UNIT_LDFLAGS := -lpthread
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lnl-3 -lnl-genl-3
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json
UNIT_LDFLAGS += $(STAGING_DIR)/usr/lib/wpa_ctrl.o 
TARGET_EXTRACFLAGS += -I $(STAGING_DIR)/usr/include/libnl3

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(TARGET_EXTRACFLAGS) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o netevd
clean:
	rm -rf netevd


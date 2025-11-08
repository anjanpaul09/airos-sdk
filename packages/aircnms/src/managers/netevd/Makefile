UNIT_SRC += src/main.c
UNIT_SRC += src/nlev.c
UNIT_SRC += src/nl.c
UNIT_SRC += src/hostapd_ev.c
UNIT_SRC += src/wpa_os_shim.c

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../libs/ds/inc
UNIT_CFLAGS += -I../../libs/log/inc
# hostapd control interface headers (override HOSTAPD_DIR if needed)
HOSTAPD_DIR ?= $(TOPDIR)/build_dir/target-mipsel_24kc_musl/hostapd-wpad-full-openssl/hostapd-2024.09.15~5ace39b0
UNIT_CFLAGS += -I$(HOSTAPD_DIR)/src/common

UNIT_CFLAGS += -Wall -Werror

UNIT_LDFLAGS := -lpthread
UNIT_LDFLAGS += -ljansson
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lnl-3 -lnl-genl-3
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json
# link hostapd control interface object (prebuilt)
UNIT_LDFLAGS += $(HOSTAPD_DIR)/build/hostapd/src/common/wpa_ctrl.o

TARGET_EXTRACFLAGS += -I $(STAGING_DIR)/usr/include/libnl3

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(TARGET_EXTRACFLAGS) $(LOC_INCS) $(CFLAGS) $(LDFLAGS) -o netevd
clean:
	rm -rf netevd


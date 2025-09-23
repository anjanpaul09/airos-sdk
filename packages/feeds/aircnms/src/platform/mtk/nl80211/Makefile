#UNIT_SRC += src/nl80211_device.c 
UNIT_SRC += src/nl80211_stats.c 
UNIT_SRC += src/nl80211_target.c 
UNIT_SRC += src/util.c
UNIT_SRC += src/nl80211_client.c 
UNIT_SRC += src/nl80211_scan.c 
UNIT_SRC += src/nl80211_survey.c 
UNIT_SRC += src/nl80211_vif_stats.c
UNIT_SRC += src/nl_util.c
UNIT_SRC += src/ext_event.c

UNIT_CFLAGS += -I. 
UNIT_CFLAGS += -I../../../include/
UNIT_CFLAGS += -Iinc/ 
UNIT_CFLAGS += -I../../../libs/ds/inc 
UNIT_CFLAGS += -I../../../libs/osa/inc 
UNIT_CFLAGS += -I../../../libs/log/inc 
UNIT_CFLAGS += -I../../../libs/common/inc 
UNIT_CFLAGS += -I../../../libs/const/inc 
UNIT_CFLAGS += -I../target/ 

UNIT_LDLAGS += -lnl-3 
UNIT_LDLAGS += -lnl-genl-3
UNIT_LDFLAGS += -lev
UNIT_LDFLAGS += -lrt
UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lds


CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
VERSION = 1.0.0
SLINK = libnl80211.so
SHARED_LIB = $(SLINK).$(VERSION)

all: clean $(SHARED_LIB)
$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) -shared -o $@ $(UNIT_SRC:.c=.o)
.c.o:
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) -c -fpic $< -o $@
clean:
	rm -rf *.o $(SLINK) $(SHARED_LIB)

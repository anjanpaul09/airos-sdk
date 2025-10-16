UNIT_SRC := src/os_time.c
UNIT_SRC += src/util.c
UNIT_SRC += src/monitor.c
UNIT_SRC += src/os.c
UNIT_SRC += src/os_util.c
UNIT_SRC += src/os_exec.c
UNIT_SRC += src/memutil.c
UNIT_SRC += src/sockaddr_storage.c
UNIT_SRC += src/iso3166.c
UNIT_SRC += src/os_backtrace.c
UNIT_SRC += src/os_nif_linux.c
UNIT_SRC += src/air_util.c

UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -Iinc/ 
UNIT_CFLAGS += -I../ds/inc 
UNIT_CFLAGS += -I../log/inc 
UNIT_CFLAGS += -I../datapipeline/inc 
UNIT_CFLAGS += -I../schema/inc
UNIT_CFLAGS += -I../target/inc 
UNIT_CFLAGS += -I../target/ 
UNIT_CFLAGS += -I../kconfig/inc

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS += -lnl-3 -lnl-genl-3

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
VERSION = 1.0.0
SLINK = libcommon.so
SHARED_LIB = $(SLINK).$(VERSION)

all: clean $(SHARED_LIB)
$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) $(OPENSYNC_FLAG) -shared -o $@ $(UNIT_SRC:.c=.o)
.c.o:
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) $(OPENSYNC_FLAG) -c -fpic $< -o $@
clean:
	rm -rf *.o $(SLINK) $(SHARED_LIB)

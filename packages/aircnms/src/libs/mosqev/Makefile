UNIT_SRC := src/mosqev.c

UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../ds/inc
UNIT_CFLAGS += -I../common/inc
UNIT_CFLAGS += -I../log/inc
UNIT_CFLAGS += -I../datapipeline/inc
UNIT_CFLAGS += -I../schema/inc
UNIT_CFLAGS += -I../target/inc
UNIT_CFLAGS += -I../target/
UNIT_CFLAGS += -I../kconfig/inc

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS += -lmosquitto
LDFLAGS += -lcrypto
LDFLAGS += -lssl

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
VERSION = 1.0.0
SLINK = libmosqev.so
SHARED_LIB = $(SLINK).$(VERSION)

all: clean $(SHARED_LIB)
$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) $(OPENSYNC_FLAG) -shared -o $@ $(UNIT_SRC:.c=.o)
.c.o:
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) $(OPENSYNC_FLAG) -c -fpic $< -o $@
clean:
	rm -rf *.o $(SLINK) $(SHARED_LIB)

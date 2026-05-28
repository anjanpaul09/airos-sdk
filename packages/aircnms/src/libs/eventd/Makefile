UNIT_SRC  := src/eventd_ubus.c
UNIT_SRC  += src/eventd_send.c

UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../../include/
UNIT_CFLAGS += -I../log/inc
UNIT_CFLAGS += -I../ds/inc
UNIT_CFLAGS += -I../common/inc


CFLAGS := $(UNIT_CFLAGS)

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
VERSION = 1.0.0
SLINK = libeventd.so
SHARED_LIB = $(SLINK).$(VERSION)

UNIT_LDFLAGS += -llog
UNIT_LDFLAGS += -lubus -lubox
# blobmsg_json: blobmsg_format_json; --no-as-needed keeps it in DT_NEEDED
UNIT_LDFLAGS += -lubus -lubox -ljson-c -lblobmsg_json


all: clean $(SHARED_LIB)
$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LOC_INCS) -shared -o $@ $(OBJ) $(UNIT_LDFLAGS) $(LDFLAGS)
.c.o:
	$(CC) $(CFLAGS) $(LOC_INCS) -c -fpic $< -o $@
clean:
	rm -rf *.o src/*.o $(SLINK) $(SHARED_LIB)

UNIT_SRC := src/dppline.c
UNIT_SRC += src/target_linux.c
UNIT_SRC += src/node.c
UNIT_SRC += ../../pbuf/aircnms_stats.pb-c.c


UNIT_CFLAGS += -Iinc/ 
UNIT_CFLAGS += -I../../pbuf/
UNIT_CFLAGS += -I../ds/inc 
UNIT_CFLAGS += -I../common/inc 
UNIT_CFLAGS += -I../log/inc 

UNIT_LDFLAGS += -lcommon
UNIT_LDFLAGS += -lprotobuf-c


CFLAGS := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
VERSION = 1.0.0
SLINK = libdatapipeline.so
SHARED_LIB = $(SLINK).$(VERSION)

all: clean $(SHARED_LIB)
$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) -shared -o $@ $(UNIT_SRC:.c=.o)
.c.o:
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) -c -fpic $< -o $@
clean:
	rm -rf *.o $(SLINK) $(SHARED_LIB)

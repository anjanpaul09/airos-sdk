# Source files for this library
UNIT_SRC := src/dhcp_fp.c

# Include dirs (current directory contains uthash.h)
UNIT_CFLAGS += -Iinc/

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
CFLAGS += $(UNIT_CFLAGS)

VERSION = 1.0.0
SLINK = libdhcpfp.so
SHARED_LIB = $(SLINK).$(VERSION)

all: clean $(SHARED_LIB)

$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $(UNIT_SRC:.c=.o)

.c.o:
	$(CC) $(CFLAGS) -c -fpic $< -o $@

clean:
	rm -rf *.o $(SLINK) $(SHARED_LIB)


UNIT_SRC  := src/unixcomm.c

UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../unixcomm/inc

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
VERSION = 1.0.0
SLINK = libunixcomm.so
SHARED_LIB = $(SLINK).$(VERSION)

all: clean $(SHARED_LIB)
$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) -shared -o $@ $(UNIT_SRC:.c=.o)
.c.o:
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) -c -fpic $< -o $@
clean:
	rm -rf *.o $(SLINK) $(SHARED_LIB)


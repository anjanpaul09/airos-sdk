UNIT_SRC  := src/unixcomm.c

UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../unixcomm/inc

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
VERSION = 1.0.0
SLINK = libunixcomm.so
SHARED_LIB = $(SLINK).$(VERSION)

TEST_SRC := tests/test_main.c
TEST_SRC += tests/test_unixcomm.c
TEST_CFLAGS := $(UNIT_CFLAGS) -I. -I../inc
TEST_LDFLAGS := -L. -lunixcomm -lcmocka

all: clean $(SHARED_LIB)
$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) -shared -o $@ $(UNIT_SRC:.c=.o)
.c.o:
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) -c -fpic $< -o $@
test: $(SHARED_LIB) test_runner
	./test_runner
test_runner: $(TEST_SRC)
	$(CC) $(TEST_CFLAGS) $(LOC_INCS) $(TEST_LDFLAGS) -o test_runner $(TEST_SRC)
clean:
	rm -rf *.o $(SLINK) $(SHARED_LIB) test_runner


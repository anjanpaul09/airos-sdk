UNIT_SRC += src/ds_tree.c

UNIT_CFLAGS += -Iinc/
UNIT_CFLAGS += -I../ds/inc
UNIT_CFLAGS += -I../log/inc
UNIT_CFLAGS += -I../datapipeline/inc
UNIT_CFLAGS += -I../schema/inc
UNIT_CFLAGS += -I../target/inc
UNIT_CFLAGS += -I../common/inc
UNIT_CFLAGS += -I../target/
UNIT_CFLAGS += -I../kconfig/inc

CFLAGS := $(UNIT_CFLAGS)
LDFLAGS += -lnl-3 -lnl-genl-3

OBJ = $(UNIT_SRC:.c=.o)

CFLAGS += -Werror=format-security -Wformat
VERSION = 1.0.0
SLINK = libds.so
SHARED_LIB = $(SLINK).$(VERSION)

TEST_SRC := tests/test_main.c
TEST_SRC += tests/test_ds_tree.c
TEST_CFLAGS := $(UNIT_CFLAGS) -I. -I../inc
TEST_LDFLAGS := -L. -lds -lcmocka

all: clean $(SHARED_LIB)
$(SHARED_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) $(OPENSYNC_FLAG) -shared -o $@ $(UNIT_SRC:.c=.o)
.c.o:
	$(CC) $(CFLAGS) $(LOC_INCS) $(LDFLAGS) $(OPENSYNC_FLAG) -c -fpic $< -o $@
test: $(SHARED_LIB) test_runner
	./test_runner
test_runner: $(TEST_SRC)
	$(CC) $(TEST_CFLAGS) $(LOC_INCS) $(TEST_LDFLAGS) -o test_runner $(TEST_SRC)
clean:
	rm -rf *.o $(SLINK) $(SHARED_LIB) test_runner

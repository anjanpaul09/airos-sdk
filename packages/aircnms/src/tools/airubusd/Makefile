UNIT_SRC := src/main.c
UNIT_SRC += src/systemhdlr.c
UNIT_SRC += src/airhdlr.c
UNIT_SRC += src/airioctl.c

UNIT_CFLAGS  += -Iinc/
UNIT_CFLAGS  += -I../../../../airdpi/src/adpi

UNIT_LDFLAGS += -lubus
UNIT_LDFLAGS += -lubox
UNIT_LDFLAGS += -ljson-c
 

CFLAGS  := $(UNIT_CFLAGS)
LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(CFLAGS) $(LDFLAGS) -o airubusd
clean:
	rm -rf airubusd

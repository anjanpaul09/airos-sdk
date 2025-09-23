UNIT_SRC += src/main.c

UNIT_CFLAGS += -I../../../../airdpi/src/adpi

# Compiler and linker flags
CFLAGS := $(UNIT_CFLAGS)
# LDFLAGS := $(UNIT_LDFLAGS)

all: clean
	$(CC) $(UNIT_SRC) $(CFLAGS) -o air_cli

clean:
	rm -rf air_cli

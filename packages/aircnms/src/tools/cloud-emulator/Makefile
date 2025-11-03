CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread
MOSQ_LDFLAGS = -lmosquitto

SRC_DIR = src
BIN = cloud-emulator
SRCS = \
  $(SRC_DIR)/main.c \
  $(SRC_DIR)/mos_sub.c \
  $(SRC_DIR)/mos_pub.c

OBJS = $(SRCS:.c=.o)

.PHONY: clean all

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(MOSQ_LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)

run: $(BIN)
	./$(BIN) config

# Compile mos_sub.c for cloud-emulator without main (define MOS_SUB_LIBRARY)
$(SRC_DIR)/mos_sub.o: $(SRC_DIR)/mos_sub.c
	$(CC) $(CFLAGS) -DMOS_SUB_LIBRARY -c -o $@ $<

# (no standalone mos-sub binary; built into cloud-emulator)




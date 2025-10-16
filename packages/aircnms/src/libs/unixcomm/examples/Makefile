# UnixComm Examples Makefile
# Builds migration examples for QM, SM, DM, and CM components

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
CFLAGS += -I../inc
CFLAGS += -L../lib
CFLAGS += -lunixcomm
CFLAGS += -lpthread

# Source files
SOURCES = qm_migration.c sm_migration.c dm_migration.c cm_migration.c
TARGETS = $(SOURCES:.c=)

# Default target
all: $(TARGETS)

# Build individual examples
qm_migration: qm_migration.c
	$(CC) $(CFLAGS) -o $@ $<

sm_migration: sm_migration.c
	$(CC) $(CFLAGS) -o $@ $<

dm_migration: dm_migration.c
	$(CC) $(CFLAGS) -o $@ $<

cm_migration: cm_migration.c
	$(CC) $(CFLAGS) -o $@ $<

# Run examples
run-qm: qm_migration
	./qm_migration

run-sm: sm_migration
	./sm_migration

run-dm: dm_migration
	./dm_migration

run-cm: cm_migration
	./cm_migration

# Run all examples
run-all: $(TARGETS)
	@echo "Running QM migration example..."
	@./qm_migration
	@echo "Running SM migration example..."
	@./sm_migration
	@echo "Running DM migration example..."
	@./dm_migration
	@echo "Running CM migration example..."
	@./cm_migration

# Clean build artifacts
clean:
	rm -f $(TARGETS)

# Install examples
install: $(TARGETS)
	install -d /usr/local/bin
	install -m 755 $(TARGETS) /usr/local/bin/

# Uninstall examples
uninstall:
	rm -f /usr/local/bin/qm_migration
	rm -f /usr/local/bin/sm_migration
	rm -f /usr/local/bin/dm_migration
	rm -f /usr/local/bin/cm_migration

# Show build information
info:
	@echo "Examples Build Information:"
	@echo "  Compiler: $(CC)"
	@echo "  Flags: $(CFLAGS)"
	@echo "  Sources: $(SOURCES)"
	@echo "  Targets: $(TARGETS)"

# Phony targets
.PHONY: all run-qm run-sm run-dm run-cm run-all clean install uninstall info

# Default target
.DEFAULT_GOAL := all

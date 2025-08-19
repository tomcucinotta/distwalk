SHELL=/bin/bash

MAKEFILE_DIR := $(dir $(firstword $(MAKEFILE_LIST)))
TOPDIR       := $(abspath $(MAKEFILE_DIR)/..)

CFLAGS=-Wall -O3
CFLAGS_DEBUG=-g -DDW_DEBUG -Wall -fprofile-arcs -ftest-coverage -fprofile-update=atomic
CFLAGS_TSAN=-g -Wall -O2 -fsanitize=thread
LDLIBS=-pthread -lm -lssl -lcrypto
LDLIBS_DEBUG=-pthread -lm -lssl -lcrypto -lgcov

TEST_PROGRAMS=test_distrib test_distrib_debug test_ccmd test_ccmd_debug test_message test_message_debug test_pqueue test_pqueue_debug
TEST_PROGRAMS+=test_queue test_queue_debug test_timespec test_timespec_debug dw_proxy dw_proxy_debug
TSAN_PROGRAMS=dw_client_tsan dw_node_tsan
DEBUG_PROGRAMS=dw_client_debug dw_node_debug
MAIN_PROGRAMS=dw_client dw_node

DW_CLIENT_SOURCES=dw_client.c ccmd.c distrib.c thread_affinity.c connection.c request.c message.c queue.c address_utils.c
DW_NODE_SOURCES=dw_node.c thread_affinity.c priority_queue.c request.c connection.c message.c address_utils.c dw_poll.c
DW_PROXY_SOURCES=dw_proxy.c address_utils.c

TEST_SCRIPTS=$(wildcard test_*.sh)
TOOLS=bash gcovr

#BUILD_DIR=.build
BUILD_DIR=.
.PRECIOUS: $(BUILD_DIR)

all: main debug tests
main:  install-manpages  $(MAIN_PROGRAMS)
debug: install-manpages  $(DEBUG_PROGRAMS) $(TSAN_PROGRAMS)
tests: install-manpages  $(TEST_PROGRAMS)

install-manpages:
	mkdir -p $(HOME)/.local/share/man/man1
	cp $(TOPDIR)/man/* $(HOME)/.local/share/man/man1/
	mandb

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

run-tests: all
	$(foreach exec,$(TOOLS),$(if $(shell which $(exec)),,$(error "No $(exec) in PATH. Please install it")))
	cd ../test && ./run-tests.sh

doc:
	doxygen

clean:
	rm -rf $(HOME)/.local/share/man/man1/
	mandb
	rm -f *.o *.gcno *.gcda *.gcov *~ *.bak log_tests.txt *.log $(MAIN_PROGRAMS) $(DEBUG_PROGRAMS) $(TSAN_PROGRAMS) $(TEST_PROGRAMS)
	rm -rf html latex gcov $(ifneq $(BUILD_DIR),.,$(BUILD_DIR))

dw_client: $(patsubst %.c,$(BUILD_DIR)/%.o,$(DW_CLIENT_SOURCES))
dw_client_debug: $(patsubst %.c,$(BUILD_DIR)/%_debug.o,$(DW_CLIENT_SOURCES))
dw_client_tsan: $(patsubst %.c,$(BUILD_DIR)/%_tsan.o,$(DW_CLIENT_SOURCES))

dw_node: $(patsubst %.c,$(BUILD_DIR)/%.o,$(DW_NODE_SOURCES))
dw_node_debug: $(patsubst %.c,$(BUILD_DIR)/%_debug.o,$(DW_NODE_SOURCES))
dw_node_tsan: $(patsubst %.c,$(BUILD_DIR)/%_tsan.o,$(DW_NODE_SOURCES))

dw_proxy: $(patsubst %.c,$(BUILD_DIR)/%.o,$(DW_PROXY_SOURCES))
dw_proxy_debug: $(patsubst %.c,$(BUILD_DIR)/%_debug.o,$(DW_PROXY_SOURCES))

test_distrib: $(patsubst %,$(BUILD_DIR)/%,test_distrib.o distrib.o)
test_distrib_debug: $(patsubst %,$(BUILD_DIR)/%,test_distrib_debug.o distrib_debug.o)
test_ccmd: $(patsubst %,$(BUILD_DIR)/%,ccmd.o queue.o test_ccmd.o distrib.o message.o)
test_ccmd_debug: $(patsubst %,$(BUILD_DIR)/%,ccmd_debug.o queue_debug.o test_ccmd_debug.o distrib.o message_debug.o)
test_message: $(patsubst %,$(BUILD_DIR)/%,queue.o test_message.o message.o)
test_message_debug: $(patsubst %,$(BUILD_DIR)/%,queue_debug.o test_message_debug.o message_debug.o)
test_pqueue: $(patsubst %,$(BUILD_DIR)/%,test_pqueue.o priority_queue.o)
test_pqueue_debug: $(patsubst %,$(BUILD_DIR)/%,test_pqueue_debug.o priority_queue_debug.o)
test_queue: $(patsubst %,$(BUILD_DIR)/%,test_queue.o queue.o)
test_queue_debug: $(patsubst %,$(BUILD_DIR)/%,test_queue_debug.o queue_debug.o)

$(BUILD_DIR)/%.d: %.c | $(BUILD_DIR)
	@$(CC) $(CFLAGS) -MM -MT '$(BUILD_DIR)/'$(<:.c=.o) -MF $@ $<

$(BUILD_DIR)/%_debug.d: %.c | $(BUILD_DIR)
	@$(CC) $(CFLAGS_DEBUG) -MM -MF $@ $<

$(BUILD_DIR)/%_tsan.d: %.c | $(BUILD_DIR)
	@$(CC) $(CFLAGS_TSAN) -MM -MF $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) -c $(CFLAGS) -o $@ $<

$(BUILD_DIR)/%_debug.o: %.c | $(BUILD_DIR)
	$(CC) -c $(CFLAGS_DEBUG) -o $@ $<

$(BUILD_DIR)/%_tsan.o: %.c | $(BUILD_DIR)
	$(CC) -c $(CFLAGS_TSAN) -o $@ $<

%: $(BUILD_DIR)/%.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%_debug: $(BUILD_DIR)/%_debug.o
	$(CC) $(CFLAGS_DEBUG) -o $@ $^ $(LDLIBS_DEBUG)

%_tsan: $(BUILD_DIR)/%_tsan.o
	$(CC) $(CFLAGS_TSAN) -o $@ $^ $(LDLIBS)

-include $(patsubst %.c,$(BUILD_DIR)/%.d $(BUILD_DIR)/%_debug.d $(BUILD_DIR)/%_tsan.d,$(wildcard *.c))

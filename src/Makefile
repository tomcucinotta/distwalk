SHELL=/bin/bash

CFLAGS=-Wall -O3 
CFLAGS_DEBUG=-g -DDW_DEBUG -fprofile-arcs -ftest-coverage
CFLAGS_TSAN=-g -O2 -fsanitize=thread
LDLIBS=-pthread -lm
LDLIBS_DEBUG=-pthread -lm -lgcov

TEST_PROGRAMS=test_distrib test_distrib_debug test_ccmd test_message test_message_debug test_ccmd_debug test_pqueue test_pqueue_debug test_queue test_queue_debug test_timespec test_timespec_debug
TSAN_PROGRAMS=dw_client_tsan dw_node_tsan
DEBUG_PROGRAMS=dw_client_debug dw_node_debug
MAIN_PROGRAMS=dw_client dw_node

TOOLS=bash gcovr

all: main debug tests
main: $(MAIN_PROGRAMS)
debug: $(DEBUG_PROGRAMS) $(TSAN_PROGRAMS)
tests: $(TEST_PROGRAMS)

run-tests: all
	$(foreach exec,$(TOOLS),$(if $(shell which $(exec)),,$(error "No $(exec) in PATH. Please install it")))
	cd ../test && ./run-tests.sh

doc:
	doxygen

clean:
	rm -f *.o *.gcno *.gcda *.gcov *~ *.bak log_tests.txt *.log $(MAIN_PROGRAMS) $(DEBUG_PROGRAMS) $(TSAN_PROGRAMS) $(TEST_PROGRAMS)
	rm -rf html latex gcov

dw_client: dw_client.o ccmd.o distrib.o thread_affinity.o connection.o request.o message.o queue.o address_utils.o
dw_client_debug: dw_client_debug.o ccmd_debug.o distrib_debug.o thread_affinity_debug.o connection_debug.o queue_debug.o request_debug.o message_debug.o address_utils_debug.o
dw_client_tsan: dw_client_tsan.o ccmd_tsan.o dw_client_tsan.o distrib_tsan.o thread_affinity_tsan.o queue.o connection.o request.o message.o address_utils_tsan.o
dw_node: dw_node.o thread_affinity.o priority_queue.o request.o connection.o message.o address_utils.o dw_poll.o
dw_node_debug: dw_node_debug.o thread_affinity_debug.o priority_queue_debug.o request_debug.o connection_debug.o message_debug.o address_utils_debug.o dw_poll_debug.o
dw_node_tsan: dw_node_tsan.o thread_affinity_tsan.o priority_queue.o request.o connection.o message.o address_utils_tsan.o dw_poll_tsan.o

test_distrib: test_distrib.o distrib.o
test_distrib_debug: test_distrib_debug.o distrib_debug.o
test_ccmd: ccmd.o queue.o test_ccmd.o distrib.o message.o
test_ccmd_debug: ccmd_debug.o queue_debug.o test_ccmd_debug.o distrib.o message_debug.o
test_message: queue.o test_message.o message.o
test_message_debug: queue_debug.o test_message_debug.o message_debug.o
test_pqueue: test_pqueue.o priority_queue.o
test_pqueue_debug: test_pqueue_debug.o priority_queue_debug.o
test_queue: test_queue.o queue.o
test_queue_debug: test_queue_debug.o queue_debug.o

%_tsan: %_tsan.o
	$(CC) -fsanitize=thread -o $@ $^ $(LDLIBS)
%_debug: %_debug.o
	$(CC) -o $@ $^ $(LDLIBS_DEBUG)

%_debug.o: %.c
	$(CC) -c $(CFLAGS_DEBUG) -o $@ $<
%_tsan.o: %.c
	$(CC) -c $(CFLAGS_TSAN)  -o $@ $<

TEST_SCRIPTS=$(wildcard test_*.sh)

dep:
	makedepend -- -Y *.c

# DO NOT DELETE

ccmd.o: ccmd.h queue.h message.h distrib.h dw_debug.h
connection.o: connection.h message.h request.h priority_queue.h dw_debug.h
distrib.o: distrib.h dw_debug.h
dw_client.o: dw_debug.h distrib.h message.h connection.h request.h address_utils.h
dw_client.o: priority_queue.h timespec.h ccmd.h
dw_node.o: dw_debug.h message.h timespec.h thread_affinity.h priority_queue.h address_utils.h
dw_node.o: request.h connection.h
message.o: message.h
address_utils.o: address_utils.h dw_debug.h
node-fwd.o: message.h timespec.h
priority_queue.o: priority_queue.h
queue.o : queue.h
request.o: request.h message.h priority_queue.h dw_debug.h
test_ccmd.o: ccmd.h message.h distrib.h dw_debug.h
test_message.o: message.h dw_debug.h
test_distrib.o: distrib.h
test_pqueue.o: priority_queue.h dw_debug.h
test_queue.o: queue.h dw_debug.h
test_timespec.o: timespec.h dw_debug.h
thread_affinity.o: thread_affinity.h

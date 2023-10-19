CFLAGS=-Wall -O3 
CFLAGS_DEBUG=-g -DCW_DEBUG
CFLAGS_TSAN=-g -O2 -fsanitize=thread
LDLIBS=-pthread -lm 

PROGRAMS=dw_client dw_node dw_client_debug dw_client_tsan dw_node_debug dw_node_tsan test_distrib test_ccmd test_struct_tsan

all: $(PROGRAMS)

clean:
	rm -f *.o *~ $(PROGRAMS)

dw_client: ccmd.o dw_client.o distrib.o thread_affinity.o
dw_client_debug: ccmd_debug.o dw_client_debug.o distrib_debug.o thread_affinity_debug.o
dw_client_tsan: dw_client_tsan.o ccmd_tsan.o dw_client_tsan.o distrib_tsan.o thread_affinity_tsan.o
dw_node: dw_node.o thread_affinity.o priority_queue.o
dw_node_debug: dw_node_debug.o thread_affinity_debug.o priority_queue.o
dw_node_tsan: dw_node_tsan.o thread_affinity_tsan.o priority_queue.o

test_distrib: test_distrib.o distrib.o
test_distrib_debug: test_distrib_debug.o distrib_debug.o
test_ccmd: ccmd.o test_ccmd.o distrib.o
test_struct_tsan: test_struct_tsan.o priority_queue.o

%_tsan: %_tsan.o
	$(CC) -fsanitize=thread -o $@ $^ $(LDLIBS)

%_debug.o: %.c
	$(CC) -c $(CFLAGS_DEBUG) $(CPPFLAGS_DEBUG) -o $@ $<
%_tsan.o: %.c
	$(CC) -c $(CFLAGS_TSAN) $(CPPFLAGS_TSAN) -o $@ $<


dep:
	makedepend -- -Y *.c

# DO NOT DELETE

ccmd.o: ccmd.h message.h distrib.h cw_debug.h
distrib.o: distrib.h cw_debug.h
thread_affinity.o: thread_affinity.h
dw_client.o: cw_debug.h distrib.h message.h timespec.h ccmd.h thread_affinity.h
dw_client_tsan.o: cw_debug.h distrib.h message.h timespec.h ccmd.h thread_affinity.h
dw_node.o: cw_debug.h message.h timespec.h thread_affinity.h
dw_node_tsan.o: cw_debug.h message.h timespec.h thread_affinity.h
thread_affinity_tsan.o: thread_affinity.h

priority_queue.o: priority_queue.h

test_ccmd.o: ccmd.h message.h distrib.h
test_distrib.o: distrib.h
test_struct_tsan.o: priority_queue.h

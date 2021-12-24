CFLAGS=-Wall -O3
CFLAGS_DEBUG=-g -DCW_DEBUG
CFLAGS_TSAN=-g -O2 -fsanitize=thread
LDLIBS=-pthread -lm

PROGRAMS=dw_client dw_node dw_client_debug dw_node_debug dw_node_tsan

all: $(PROGRAMS)

clean:
	rm -f *.o *~ $(PROGRAMS)

dw_client: dw_client.o expon.o
dw_client_debug: dw_client_debug.o expon_debug.o
dw_node: dw_node.o
dw_node_debug: dw_node_debug.o
test_expon: test_expon.o expon.o

%_tsan: %_tsan.o
	$(CC) -fsanitize=thread -o $@ $< $(LDLIBS)

%_debug.o: %.c
	$(CC) -c $(CFLAGS_DEBUG) $(CPPFLAGS_DEBUG) -o $@ $<
%_tsan.o: %.c
	$(CC) -c $(CFLAGS_TSAN) $(CPPFLAGS_TSAN) -o $@ $<


dep:
	makedepend -- -Y *.c

# DO NOT DELETE

dw_client.o: message.h timespec.h cw_debug.h expon.h
dw_node.o: message.h timespec.h cw_debug.h
test_expon.o: expon.h

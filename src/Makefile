CFLAGS=-Wall -O3
CFLAGS_DEBUG=-g -DCW_DEBUG
CFLAGS_TSAN=-g -O2 -fsanitize=thread
LDLIBS=-pthread -lm

PROGRAMS=client node client_debug node_debug node_tsan

all: $(PROGRAMS)

clean:
	rm -f *.o *~ $(PROGRAMS)

client: client.o expon.o
client_debug: client_debug.o expon_debug.o
test_expon: test_expon.o expon.o
%_tsan: %_tsan.o
	$(CC) $(LDLIBS) -fsanitize=thread -o $@ $<


%_debug.o: %.c
	$(CC) -c $(CFLAGS_DEBUG) $(CPPFLAGS_DEBUG) -o $@ $<
%_tsan.o: %.c
	$(CC) -c $(CFLAGS_TSAN) $(CPPFLAGS_TSAN) -o $@ $<


dep:
	makedepend -- -Y *.c

# DO NOT DELETE

client.o: message.h timespec.h cw_debug.h expon.h
node.o: message.h timespec.h cw_debug.h

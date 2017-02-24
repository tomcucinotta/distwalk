CFLAGS=-g
LDFLAGS=-pthread

all: client node

clean:
	rm -f *.o client node

dep:
	makedepend -- -Y *.c

# DO NOT DELETE

client.o: message.h timespec.h cw_debug.h
node.o: message.h timespec.h cw_debug.h

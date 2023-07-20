
all:
	cd src && make && cp dw_node dw_client ../

clean:
	rm -f *~
	cd src && make clean

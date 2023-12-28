
all:
	cd src && make && cp dw_node dw_client ../

cov:
	cd src && make cov
clean:
	rm -f *~
	cd src && make clean

all:
	cd src && make all

run-tests: all
	cd test && ./run-tests.sh

cov-scan: clean

clean:
	rm -f *~ dw_node dw_client dw_node_debug dw_client_debug
	cd src && make clean
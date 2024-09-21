main:
	cd src && make main && cp dw_node dw_client ../
debug:
	cd src && make debug && cp dw_node_debug dw_client_debug ../
all:
	cd src && make all && cp dw_node dw_client dw_node_debug dw_client_debug ../

run-tests:
	cd src && make all
	cd test && ./run-tests.sh

clean:
	rm -f *~ dw_node dw_client dw_node_debug dw_client_debug
	cd src && make clean

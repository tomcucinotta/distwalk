all:
	cd src && make all && cp dw_node dw_client dw_node_debug dw_client_debug dw_node_tsan dw_client_tsan ../

run-tests:
	cd src && make all
	cd test && ./run-tests.sh

clean:
	rm -f *~ dw_node dw_client dw_node_debug dw_client_debug
	cd src && make clean

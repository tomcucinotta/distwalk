all: install-manpages
	cd src && make all

run-tests: all
	cd test && ./run-tests.sh

cov-scan: clean

install-manpages:
	mkdir -p $(HOME)/.local/share/man/man1
	cp man/* $(HOME)/.local/share/man/man1/

clean:
	rm -f *~ dw_node dw_client dw_node_debug dw_client_debug
	rm -rf $(HOME)/.local/share/man/man1/
	cd src && make clean
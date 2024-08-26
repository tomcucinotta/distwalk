#!/bin/bash

trap 'jobs -p | while read pid; do kill -SIGUSR1 $pid; done; wait' SIGINT SIGTERM EXIT ERR
set -e

TMP=$(mktemp /tmp/dw-store-XXX.dat)

./dw_node_debug -s $TMP &
./dw_client_debug -S 65536
[ $(du -b $TMP | cut -f1) -eq 65536 ]

./dw_client_debug -L 65536

rm $TMP

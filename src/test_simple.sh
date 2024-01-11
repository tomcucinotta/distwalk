#!/bin/bash

trap 'jobs -p | while read pid; do kill $pid; done; wait' SIGINT SIGTERM EXIT

./dw_node &
./dw_client
./dw_client -n 10
./dw_client -C 10000

exit

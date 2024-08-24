#!/bin/bash

trap 'jobs -p | while read pid; do kill $pid; done; wait' SIGINT SIGTERM EXIT ERR
set -e

./dw_node_debug --udp=7891 &
./dw_client_debug --udp=127.0.0.1:7891
./dw_client_debug --udp=127.0.0.1:7891 -n 10
./dw_client_debug --udp=127.0.0.1:7891 -C 10000

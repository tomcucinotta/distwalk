#!/bin/bash

trap 'jobs -p | while read pid; do kill $pid; done; wait' SIGINT SIGTERM EXIT ERR
set -e

./dw_node_debug --help
./dw_client_debug --help

./dw_node_debug &
./dw_client_debug
./dw_client_debug -n 10
./dw_client_debug -C 10000

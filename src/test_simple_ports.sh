#!/bin/bash

trap 'jobs -p | while read pid; do kill $pid; done; wait' SIGINT SIGTERM EXIT ERR
set -e

./dw_node_debug --tcp=7894 &
./dw_client_debug || true
./dw_client_debug --tcp=127.0.0.1:7894

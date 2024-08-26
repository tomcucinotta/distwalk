#!/bin/bash

trap 'jobs -p | while read pid; do kill -SIGUSR1 $pid; done; wait' SIGINT SIGTERM EXIT ERR
set -e

./dw_node_debug &
./dw_client_debug -C 10000
elapsed=$(./dw_client_debug -C 10000 | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 10000 ] && [ $elapsed -lt 20000 ]
elapsed=$(./dw_client_debug -C 10000 -C 20000 | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 30000 ] && [ $elapsed -lt 40000 ]

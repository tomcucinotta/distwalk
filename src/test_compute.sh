#!/bin/bash

trap 'jobs -p | while read pid; do kill $pid; done; wait' SIGINT SIGTERM EXIT

./dw_node &
./dw_client -C 10000
elapsed=$(./dw_client -C 10000 | grep elapsed | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 10000 ] && [ $elapsed -lt 20000 ] || exit 1
elapsed=$(./dw_client -C 10000 -C 20000 | grep elapsed | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 30000 ] && [ $elapsed -lt 40000 ] || exit 1

exit

#!/bin/bash

if [ "$1" = "" ]; then
    echo "Usage: $0 nclients"
    exit -1
fi

../src/dw_node -s ../src/test.data &

for i in $(seq 1 1 $1)
do
        ../src/dw_client -S 1000 -n 4 &
done

sleep 2

kill -SIGINT $(pgrep node)
wait

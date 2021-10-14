#!/bin/bash

if [ "$1" = "" ]; then
    echo "Usage: $0 nclients"
    exit -1
fi

../src/node -s ../src/test.data &

for i in $(seq 1 1 $1)
do
        ../src/client -n 2 -s 2 -S 100000 &
done

sleep 2

kill -SIGINT $(pgrep node)
wait

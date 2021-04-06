#!/bin/bash

if [ "$1" = "" ]; then
    echo "Usage: $0 nclients"
    exit -1
fi

../src/node &

for i in $(seq 1 1 $1)
do
	../src/client -c 10 &
done

sleep 2

kill -SIGINT $(pgrep node)
wait

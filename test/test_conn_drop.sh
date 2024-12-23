#!/bin/bash

. common.sh

node_bg

(client -n 3 -C 100000 -p 1000000 || true) &
sleep 0.5
kill -SIGINT $(pidof dw_client_debug)
kill -SIGINT $(pidof dw_node_debug)

node_bg

(client -n 3 -C 800000 -p 1000000 || true) &
sleep 0.1
while ! kill -SIGINT $(pidof dw_client_debug); do
    echo "Retrying kill of dw_client_debug..."
done

for ((i=0; i<10; i++)); do
    (client -n 3 -C 800000 -p 1000000 || true) &
    sleep 0.$(printf "%06d\n" $[ $RANDOM * 1000000 / 65536 ])
    while ! kill -SIGINT $(pidof dw_client_debug); do
          echo "Retrying kill of dw_client_debug..."
    done
done

for ((i=0; i<100; i++)); do
    (client -n 1000 -C 100 -p 1000 --ps=$[ 4 * 1024 * 1024 ] || true) &
    while ! kill -SIGINT $(pidof dw_client_debug); do
          echo "Retrying kill of dw_client_debug..."
    done
done

kill_all SIGKILL

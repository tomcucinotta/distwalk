#!/bin/bash

. common.sh

TMP1=$(mktemp /tmp/dw-node-stats-1-XXX.dat)
TMP2=$(mktemp /tmp/dw-node-stats-2-XXX.dat)

echo "step 1"
node_bg -b :7891 &> $TMP1

kill -SIGUSR1 `pidof dw_node_debug`
grep -q "worker-id: 0, active-conns: 0, active-reqs: 0" $TMP1

client -C 1000

kill -SIGUSR1 `pidof dw_node_debug`
cnt=$(grep -c "worker-id: 0, active-conns: 0, active-reqs: 0" $TMP1)
[ $cnt -eq 2 ]


client_bg -C 1000 -n 200

sleep 1
kill -SIGUSR1 `pidof dw_node_debug`
grep -q "worker-id: 0, active-conns: 1" $TMP1
cnt=$(grep -c "worker-id: 0, active-conns: 0, active-reqs: 0" $TMP1)
[ $cnt -eq 2 ]

kill_all SIGINT


echo "step 2"
node_bg -b :7891 &> $TMP1

client_bg -C 1000 -n 200
client_bg -C 1000 -n 200
sleep 1

kill -SIGUSR1 `pidof dw_node_debug`
grep -q "worker-id: 0, active-conns: 2, active-reqs: 0" $TMP1

kill_all SIGINT
wait $(pidof dw_client_debug)

echo "step 3"
node_bg -b :7891 &> $TMP1
node_bg -b :7892 &> $TMP2
sleep 1

client_bg -C 1000 -F :7892 -C 100 -n 1000
sleep 1
kill -SIGUSR1 `pidof dw_node_debug`

kill -SIGINT `pidof dw_client_debug`
kill -SIGUSR1 `pidof dw_node_debug`

grep -q "worker-id: 0, active-conns: 1" $TMP1
grep -q "worker-id: 0, active-conns: 1" $TMP2

rm $TMP1
rm $TMP2

#!/bin/bash

. common.sh

TMP1=$(mktemp /tmp/dw-node-stats-1-XXX.dat)
TMP2=$(mktemp /tmp/dw-node-stats-2-XXX.dat)

echo "step 1"
node_bg -b :7891 &> $TMP1

kill -SIGUSR1 `pidof dw_node_debug`
cat $TMP1 | grep -q "worker-id: 0, active-conns: 0, active-reqs: 0"

client -C 1000

kill -SIGUSR1 `pidof dw_node_debug`
cnt=$(cat $TMP1 | grep "worker-id: 0, active-conns: 0, active-reqs: 0" | wc -l)
[ $cnt -eq 2 ]


client_bg -C 1000 -n 200

sleep 1
kill -SIGUSR1 `pidof dw_node_debug`
cat $TMP1 | grep -q "worker-id: 0, active-conns: 1"
cnt=$(cat $TMP1 | grep "worker-id: 0, active-conns: 0, active-reqs: 0" | wc -l)
[ $cnt -eq 2 ]

kill_all SIGINT


echo "step 2"
node_bg -b :7891 &> $TMP1

client_bg -C 1000 -n 200
client_bg -C 1000 -n 200
sleep 1

kill -SIGUSR1 `pidof dw_node_debug`
cat $TMP1 | grep -q "worker-id: 0, active-conns: 2, active-reqs: 0"

kill_all SIGINT

echo "step 3"
node_bg -b :7891 &> $TMP1
pid1=$!
node_bg -b :7892 &> $TMP2
pid2=$!
sleep 1

client_bg -C 1000 -F :7892 -C 100 -n 1000
sleep 2
kill -SIGUSR1 $pid1
kill -SIGUSR1 $pid2

cat $TMP1 | grep -q "worker-id: 0, active-conns: 2"
cat $TMP2 | grep -q "worker-id: 0, active-conns: 1"

wait `pidof dw_client_debug`
kill -SIGUSR1 $pid1
kill -SIGUSR1 $pid2
cat $TMP1 | grep -q "worker-id: 0, active-conns: 1"
cat $TMP2 | grep -q "worker-id: 0, active-conns: 1"

#rm $TMP1
#rm $TMP2

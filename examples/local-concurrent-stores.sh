#!/bin/bash

# NOTE, if you are using the tsan version of dw components, make sure to reduce the
#  the amount of randomization in the virtual memory with:
# `sudo sysctl vm.mmap_rnd_bits=28`
# (default is 32 bits on Ubuntu 24.04 LTS, Kernel 6.8.0-40-generic)

function clean_up {
    kill -SIGINT $NODEPID
    exit
}

trap clean_up SIGHUP SIGINT SIGTERM

if [ ! $# -eq 2 ]; then
    echo "Usage: $0 <num-clients> <node-threads>"
    exit -1
fi
NUM_CLIENTS=$1
NUM_THREADS=$2

rm /tmp/dw_client_stores_*.log

../src/dw_node --nt $NUM_THREADS -s ../src/test.data &> /tmp/dw_node_stores.log &
NODEPID=$!

sleep 1
CLIENTPIDS=()
for i in $(seq 1 1 $NUM_CLIENTS)
do
	../src/dw_client -S 10000 -n 5 &> /tmp/dw_client_stores_$i.log &
    CLIENTPIDS[${i}]=$!
done

# wait
for PID in ${CLIENTPIDS[@]}; do
    wait $PID
done

echo "Full results in /tmp/dw_client_stores_*.log"
tail -n -10 /tmp/dw_client_stores_*.log

sleep 1
clean_up

#!/bin/bash

# NOTE, if you are using the tsan version of dw components, make sure to reduce the 
#  the amount of randomization in the virtual memory with:
# `sudo sysctl vm.mmap_rnd_bits=28` 
# (default is 32 bits on Ubuntu 24.04 LTS, Kernel 6.8.0-40-generic) 

function clean_up {
    kill -SIGINT $NODEPID_L $NODEPID_R
    exit
}

trap clean_up SIGHUP SIGINT SIGTERM

if [ ! $# -eq 3 ]; then
    echo "Usage: $0 <num-left-to-right-clients> <num-right-to-left-clients> <node-threads>"
    exit -1
fi
NUM_LR_CLIENTS=$1
NUM_RL_CLIENTS=$2
NUM_THREADS=$3

rm /tmp/dw_client_cross_fwd_*.log

../src/dw_node --nt $NUM_THREADS --tcp 7000 &> /tmp/dw_node_cross_fwd_L.log &
NODEPID_L=$!
../src/dw_node --nt $NUM_THREADS --tcp 7001 &> /tmp/dw_node_cross_fwd_R.log &
NODEPID_R=$!

sleep 1
CLIENTPIDS_LR=()
for i in $(seq 1 1 $NUM_LR_CLIENTS)
do
	../src/dw_client --tcp :7000 -C 1000 -F :7001 -C 2000 -n 50 &> /tmp/dw_client_cross_fwd_LR_$i.log &
    CLIENTPIDS_LR[${i}]=$!
done

CLIENTPIDS_RL=()
for i in $(seq 1 1 $NUM_RL_CLIENTS)
do
    ../src/dw_client --tcp :7001 -C 1000 -F :7000 -C 2000 -n 50 &> /tmp/dw_client_cross_fwd_RL_$i.log &
    CLIENTPIDS_RL[${i}]=$!
done

# wait
CLIENTPIDS=("${CLIENTPIDS_LR[@]}" "${CLIENTPIDS_RL[@]}")
for PID in ${CLIENTPIDS[@]}; do
    wait $PID
done


echo "Full results in /tmp/dw_client_cross_fwd_*.log"
tail -n -10 /tmp/dw_client_cross_fwd_*.log

sleep 1
clean_up

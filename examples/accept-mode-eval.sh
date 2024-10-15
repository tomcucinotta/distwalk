#!/bin/bash

# NOTE, if you are using the tsan version of dw components, make sure to reduce the 
#  the amount of randomization in the virtual memory with:
# `sudo sysctl vm.mmap_rnd_bits=28` 
# (default is 32 bits on Ubuntu 24.04 LTS, Kernel 6.8.0-40-generic) 

NODEPID=
CLIENTPIDS=()

function cleanup {
    kill -SIGINT $@
}

trap "cleanup $NODEPID; exit" SIGHUP SIGINT SIGTERM

if [ $# -lt 2 ]; then
    echo "Usage: $0 <num-clients> <node-threads> [<parent|shared|child>]"
    exit -1
fi
NUM_CLIENTS=$1
NUM_THREADS=$2
ACCEPT_MODE="child"
if [ $# -eq 3 ]; then
    ACCEPT_MODE=$3
fi

cleanup `pidof dw_node`
cleanup `pidof dw_node_debug`
cleanup `pidof dw_node_tsan`

NODETMP=/tmp/dw-node-accept-mode-eval.dat

../src/dw_node_debug --nt $NUM_THREADS &> $NODETMP &
NODEPID=$!

sleep 1
if ! ps -p $NODEPID > /dev/null; then
   echo "Node terminated prematurely"
   exit -1
fi

rm /tmp/dw-client-accept-mode-eval-*.dat
CLIENTPIDS=()
for i in $(seq 1 1 $NUM_CLIENTS); do
    CLIENTTMP=/tmp/dw-client-accept-mode-eval-$i.dat
	../src/dw_client_debug -C 1 -n 150 --ns 50 &> $CLIENTTMP &
    CLIENTPIDS[${i}]=$!
done

# wait
for PID in ${CLIENTPIDS[@]}; do
    wait $PID
done

echo "Full results in /tmp/dw-client-accept-mode-eval-*.dat"
tail -n -10 /tmp/dw-client-accept-mode-eval-*.dat

../script/ctx-switches.sh $NODEPID &> dw-client-accept-mode-eval-ctx_switches_nt$(printf "%02d" $i)_am$am.csv

#awk '/^Name:|^voluntary_ctxt_switches:|^nonvoluntary_ctxt_switches:/ { print $1, $2 }' /proc/$NODEPID/task/*/status

cleanup $NODEPID

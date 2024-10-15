#!/bin/bash

kill `pidof dw_node` &> /dev/null
kill `pidof dw_node_debug` &> /dev/null
kill `pidof dw_node_tsan` &> /dev/null

# Input args
if [ -z "$1" ]; then
    echo "Usage: $0 <node-threads> [accept-mode] [taskset]"
    exit -1
fi
NUM_THREADS=$1

ACCEPT_MODE="child"
if [ ! -z "$2" ]; then
    ACCEPT_MODE=$2
fi

TASKSET=
if [ ! -z "$3" ]; then
    TASKSET="-c $3"
fi

sudo ../script/cpu-setup.sh > /dev/null

../src/dw_node --nt=$NUM_THREADS -a $ACCEPT_MODE $TASKSET &
nodepid=$!
sleep 1

rampup_log=$(mktemp /tmp/ramp-up_nt$(printf "%02d" $NUM_THREADS)_am$ACCEPT_MODE-XXX.log)
../src/dw_client -C 100000 -r 1 --ramp-step-secs=1 --ramp-delta-rate=1 --ramp-num-steps=30 --ns 465 &> $rampup_log

kill $nodepid &> /dev/null


sudo ../script/cpu-teardown.sh > /dev/null

../script/log2csv.sh $rampup_log > ${rampup_log/.log/.csv}

echo "Results in:"
printf "\t$rampup_log\n"

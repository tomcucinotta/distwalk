#!/bin/bash

. common.sh

tmp=$(mktemp /tmp/test_affinity-XXX.txt)

strace_node_bg --thread-affinity=auto &> $tmp
kill_all SIGINT
grep "sched_setaffinity(" $tmp

for nt in 2 4; do
    strace_node_bg --num-threads=$nt --thread-affinity=auto &> $tmp
    kill_all SIGINT
    for i in $(seq 0 $[ $nt - 1 ]); do
        grep "sched_setaffinity(.*\[$i\]" $tmp
    done
done

strace_node_bg --thread-affinity=2-2 &> $tmp
kill_all SIGINT
grep "sched_setaffinity(.*\[2\]" $tmp

strace_node_bg --thread-affinity=2 &> $tmp
kill_all SIGINT
grep "sched_setaffinity(.*\[2\]" $tmp

rm $tmp

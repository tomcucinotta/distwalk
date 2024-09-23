#!/bin/bash

. common.sh

node_bg --sched-policy=other
kill_all SIGINT

# needs to fail: non-existing policy
! node_bg --sched-policy=xxx

# needs to fail: needs rr:rtprio syntax
! node_bg --sched-policy=rr

if [ "$(whoami)" == "root" ]; then
    node_bg --sched-policy=rr:7
    chrt -a -p $(pidof dw_node_debug) | grep -q "current scheduling policy: SCHED_RR"
    chrt -a -p $(pidof dw_node_debug) | grep -q "current scheduling priority: 7"
    kill_all SIGINT

    node_bg --sched-policy=rr:7 --nt=2
    [ $(chrt -a -p $(pidof dw_node_debug) | grep -c "current scheduling policy: SCHED_RR") -eq 2 ]
    [ $(chrt -a -p $(pidof dw_node_debug) | grep -c "current scheduling priority: 7") -eq 2 ]
    kill_all SIGINT
fi

# needs to fail: needs fifo:rtprio syntax
! node_bg --sched-policy=fifo

if [ "$(whoami)" == "root" ]; then
    node_bg --sched-policy=fifo:7
    chrt -a -p $(pidof dw_node_debug) | grep -q "current scheduling policy: SCHED_FIFO"
    chrt -a -p $(pidof dw_node_debug) | grep -q "current scheduling priority: 7"
    kill_all SIGINT

    node_bg --wait-bind-num 2 --sched-policy=fifo:7 --nt=2
    [ $(chrt -a -p $(pidof dw_node_debug) | grep -c "current scheduling policy: SCHED_FIFO") -eq 2 ]
    [ $(chrt -a -p $(pidof dw_node_debug) | grep -c "current scheduling priority: 7") -eq 2 ]
    kill_all SIGINT
fi

# needs to fail: needs dl:runtime_us,deadline_us syntax
! node_bg --sched-policy=dl
! node_bg --sched-policy=dl:10000

if [ "$(whoami)" == "root" ]; then
    node_bg --sched-policy=dl:10000,20000
    chrt -a -p $(pidof dw_node_debug) | grep -q "current scheduling policy: SCHED_DEADLINE"
    chrt -a -p $(pidof dw_node_debug) | grep -q "current scheduling runtime/deadline/period parameters: 10000000/20000000/20000000"
    kill_all SIGINT

    node_bg --sched-policy=dl:10000,20000 --nt=2
    [ $(chrt -a -p $(pidof dw_node_debug) | grep -c "current scheduling policy: SCHED_DEADLINE") -eq 2 ]
    [ $(chrt -a -p $(pidof dw_node_debug) | grep -c "current scheduling runtime/deadline/period parameters: 10000000/20000000/20000000") -eq 2 ]
    kill_all SIGINT
fi

# This is needed when launched as non-root
exit 0

#!/bin/bash

. common.sh

node_bg

client -C 500 -n 10 -p 1000
client -C 500 -n 10 -r 1000

t1=$(date +%s)
client -C 500 -n 10 -p 100000
t2=$(date +%s)
echo $t2-$t1=$[$t2-$t1]
[ $[ $t2 - $t1 ] -ge 1 -a $[ $t2 - $t1 ] -lt 2 ]

t1=$(date +%s)
client -C 500 -n 10 -r 10
t2=$(date +%s)
echo $t2-$t1=$[$t2-$t1]
[ $[ $t2 - $t1 ] -ge 1 -a $[ $t2 - $t1 ] -lt 2 ]

client --send-pkt-size=1024
client --resp-pkt-size=1024
client --nd 0 -C 1000
client --nd 1 -C 1000
strace_client --nd=0 2>&1 | grep sockopt | grep 'TCP_NODELAY, \[0\]'
strace_client --nd=1 2>&1 | grep sockopt | grep 'TCP_NODELAY, \[1\]'

client -C 500 -n 100 -r 1 --ramp-step-secs=1 --ramp-delta-rate=1 --ramp-num-steps=10
client -C 500 -n 100 -r 1 --ramp-filename=<(echo -e "1\n2\n3\n4\n5\n6\n7\n8\n9\n10")

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
client --reply=1024
client --nd 0 -C 1000
client --nd 1 -C 1000
strace_client --nd=0 2>&1 | grep sockopt | grep 'TCP_NODELAY, \[0\]'
strace_client --nd=1 2>&1 | grep sockopt | grep 'TCP_NODELAY, \[1\]'

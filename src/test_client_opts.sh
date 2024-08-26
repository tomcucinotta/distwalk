#!/bin/bash

. common.sh

node_bg

client -C 500 -n 10 -p 1000
client -C 500 -n 10 -r 1000
client --send-pkt-size=1024
client --resp-pkt-size=1024
client --nd 0 -C 1000
client --nd 1 -C 1000
strace_client --nd=0 2>&1 | grep sockopt | grep 'TCP_NODELAY, \[0\]'
strace_client --nd=1 2>&1 | grep sockopt | grep 'TCP_NODELAY, \[1\]'

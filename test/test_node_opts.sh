#!/bin/bash

. common.sh

node_bg
[ $(ps H -o 'pid tid cmd comm' | grep connw | grep -v grep | wc -l) -eq 1 ]

kill_all SIGINT

node_bg --num-threads=2
[ $(ps H -o 'pid tid cmd comm' | grep connw | grep -v grep | wc -l) -eq 2 ]

tmp=$(mktemp /tmp/test_node_opts-XXX.txt)

node_bg -b :7000 &> $tmp
cat $tmp | grep -q "Node bound to 127.0.0.1:7000 (with protocol: TCP)"
kill_all SIGINT

node_bg -b udp://:7000 &> $tmp
cat $tmp | grep -q "Node bound to 127.0.0.1:7000 (with protocol: UDP)"
kill_all SIGINT

node_bg -b udp:// &> $tmp
cat $tmp | grep -q "Node bound to 127.0.0.1:7891 (with protocol: UDP)"
kill_all SIGINT

node_bg -b udp::7000 &> $tmp
cat $tmp | grep -q "Error"
kill_all SIGINT

node_bg -b udp:tcp://:7000 &> $tmp
cat $tmp | grep -q "Error"
kill_all SIGINT

node_bg -b :7000://:tcp &> $tmp
cat $tmp | grep -q "Error"
kill_all SIGINT

strace_node_bg --nd=0 &> $tmp
client
kill_all SIGINT
grep sockopt $tmp | grep 'TCP_NODELAY, \[0\]'

strace_node_bg --nd=1 &> $tmp
client
kill_all SIGINT
grep sockopt $tmp | grep 'TCP_NODELAY, \[1\]'

node_bg --ws
client
kill_all SIGINT

rm $tmp

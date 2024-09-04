#!/bin/bash

# ASSUMPTION: round-robin load balacing

. common.sh

tmp=$(mktemp /tmp/test_accept_mode_parent-XXX.dat)

node_bg -a parent --nt 3 &> $tmp

client -C 1000 -n 1 --ns 3

cat $tmp | grep -q "[connw\-0] conn_id: 0 assigned to connw\-0"
cat $tmp | grep -q "[connw\-0] conn_id: 0 assigned to connw\-1"
cat $tmp | grep -q "[connw\-0] conn_id: 0 assigned to connw\-2"

kill_all SIGINT
rm $tmp


node_bg -a parent --nt 2

elapsed=($(client -C 1000000 -p 1000000 --nt 4 | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//'))

[ ${elapsed[0]} -gt 999000 ] && [ $elapsed -lt 1001000 ]
[ ${elapsed[1]} -gt 999000 ] && [ $elapsed -lt 1001000 ]
[ ${elapsed[2]} -gt 1999000 ] && [ $elapsed -lt 2001000 ]
[ ${elapsed[3]} -gt 1999000 ] && [ $elapsed -lt 2001000 ]

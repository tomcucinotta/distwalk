#!/bin/bash

# ASSUMPTION: round-robin load balacing

mydir=$(dirname "$0")
source "$mydir/common.sh"

tmp=$(mktemp /tmp/dw-test_accept_mode_parent-0-XXX.txt)

node_bg -a parent --nt 3 &> $tmp

client -C 1000 -n 3 --ns 3

cat $tmp | grep assigned | head -1 | grep -q "assigned to dwn_conn_0"
cat $tmp | grep assigned | head -2 | tail -1 | grep -q "assigned to dwn_conn_1"
cat $tmp | grep assigned | head -3 | tail -1 | grep -q "assigned to dwn_conn_2"

kill_all SIGINT
cat $tmp
rm $tmp

tmp=$(mktemp /tmp/dw-test_accept_mode_parent-1-XXX.txt)

node_bg -a parent --nt 2

client -C 1s -p 1s --nt 4 &> $tmp

elapsed=($(cat $tmp | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//'))

[ ${elapsed[0]} -gt 990000 ] && [ $elapsed -lt 1010000 ]
[ ${elapsed[1]} -gt 990000 ] && [ $elapsed -lt 1010000 ]
[ ${elapsed[2]} -gt 1990000 ] && [ $elapsed -lt 2010000 ]
[ ${elapsed[3]} -gt 1990000 ] && [ $elapsed -lt 2010000 ]

kill_all SIGINT
cat $tmp
rm $tmp

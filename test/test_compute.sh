#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

tmp_node=$(tmpfile dw-test_compute-node)
tmp_client=$(tmpfile dw-test_compute-client)

node_bg > $tmp_node

client -b :8000 -C 10000 > $tmp_client
elapsed=$(cat $tmp_client | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 10000 ] && [ $elapsed -lt 20000 ]

client -b :8001 -C 10000 -C 20000 > $tmp_client
elapsed=$(cat $tmp_client | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 30000 ] && [ $elapsed -lt 40000 ]

grep -q "Accepted connection from: 127.0.0.1:8000" $tmp_node
grep -q "Accepted connection from: 127.0.0.1:8001" $tmp_node

kill_all SIGINT

rm $tmp_client
rm $tmp_node

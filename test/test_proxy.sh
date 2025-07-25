#!/bin/bash

. common.sh

tmp_node=$(mktemp /tmp/dw-node-XXX.dat)
tmp_client=$(mktemp /tmp/dw-client-XXX.dat)

node_bg -b :7892 &> $tmp_node
../src/dw_proxy -b :7891 --to :7892 &
client --to :7891 -C 0 -n 1 &> $tmp_client

kill_all SIGKILL

grep -q "success: 1," $tmp_client
elapsed=$(grep 'elapsed:' $tmp_client | sed -e 's/.*elapsed: //; s/ us.*//')
echo elapsed=$elapsed
[ $elapsed -lt 10000 ]

node_bg -b :7892 &> $tmp_node
../src/dw_proxy -b :7891 --to :7892 -d 10 &
client --to :7891 -C 0 -n 1 &> $tmp_client

grep -q "success: 1," $tmp_client
elapsed=$(grep 'elapsed:' $tmp_client | sed -e 's/.*elapsed: //; s/ us.*//')
echo elapsed=$elapsed
[ $elapsed -ge 10000 ]

kill_all SIGKILL

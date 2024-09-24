#!/bin/bash

set -x
. common.sh

node_bg -b :7891
client -C 1000 -F :7892 -C 2000 | grep -q "Got complete message (req_id: 0, req_size: 512, num: 0, status: -1)"
kill_all SIGINT

node_bg -b :7891
node_bg -b :7892
client -C 1000 -F :7892 -C 2000 | grep -q "Got complete message (req_id: 0, req_size: 512, num: 0, status: 0)"
kill_all SIGINT


tmp=$(mktemp /tmp/test_forward_timeout-XXX.dat)
node_bg -b :7891
client_bg -C 1000 -F timeout=5000000,retry=5,:7892 -C 2000 &> $tmp

sleep 2
node_bg -b :7892
sleep 2

grep -q "Got complete message (req_id: 0, req_size: 512, num: 0, status: 0)" $tmp

rm $tmp
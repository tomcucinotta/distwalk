#!/bin/bash

set -x
. common.sh

#
node_bg -b :7891
client -C 1000 -F :7892 -C 2000 | grep -q "received message: message (req_id: 0, req_size: 512, num: 0, status: -1)"
kill_all SIGINT

node_bg -b :7891
node_bg -b :7892
client -C 1000 -F :7892 -C 2000 | grep -q "received message: message (req_id: 0, req_size: 512, num: 0, status: 0)"
kill_all SIGINT

#
tmp=$(mktemp /tmp/test_forward_timeout-XXX.dat)
node_bg -b :7891
client_bg -C 1000 -F timeout=500000,retry=50,:7892 -C 2000 &> $tmp

sleep 2
node_bg -b :7892

attempt=1
while ! grep -q "received message: message (req_id: 0, req_size: 512, num: 0, status: 0)" $tmp; do
    echo "re-check $attempt"
    sleep 1

    if [[ $attempt -eq 5 ]]; then
        exit -1
    fi
    ((attempt++))
done

kill_all SIGINT

#
node_bg -b :7891
node_bg -b :7892

client --to :7891 -C 100 -F :7892 -C 200 -F :7893 -C 300 | grep -q "received message: message (req_id: 0, req_size: 512, num: 0, status: -1)"
kill_all SIGINT

#
node_bg -b :7891
node_bg -b :7892

tmp=$(mktemp /tmp/test_forward_timeout-XXX.dat)
client --to :7891 -C 100 -F :7892,:7893 -C 200 &> $tmp 
attempt=1
while ! grep -q "received message: message (req_id: 0, req_size: 512, num: 0, status: -1)" $tmp; do
    echo "re-check $attempt"
    sleep 1

    if [[ $attempt -eq 5 ]]; then
        exit -1
    fi
    ((attempt++))
done

client --to :7891 -C 100 -F :7892,:7893 -C 200 --rs=1000,nack=1 | grep -q "received message: message (req_id: 0, req_size: 512, num: 0, status: 0)"
kill_all SIGINT

rm $tmp

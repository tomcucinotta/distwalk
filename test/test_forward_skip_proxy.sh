#!/bin/bash

. common.sh

TMP_N0=$(mktemp /tmp/dw-node-fwd-1-XXX.txt)
TMP_N1=$(mktemp /tmp/dw-node-fwd-2-XXX.txt)
TMP_C0=$(mktemp /tmp/dw-client-fwd-XXX.txt)

node_bg -b :7891 &> $TMP_N0
proxy_bg -b :7892 --to :7893 -d 10
node_bg -b :7893 &> $TMP_N1

client -C 1000 --skip=1,every=2 -F localhost:7892 -C 10ms -n 10 &> $TMP_C0

# even req_id got response times < 10ms, odd ones > 10ms
[ $(grep 'elapsed: .*req_id: [02468]' $TMP_C0 | grep -c 'elapsed: [0-9]\{4\} us') == 5 ]
[ $(grep 'elapsed: .*req_id: [13579]' $TMP_C0 | grep -c 'elapsed: [0-9]\{5\} us') == 5 ]

kill_all SIGINT

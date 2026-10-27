#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

TMP_N0=$(tmpfile dw-test_forward_skip-node-0)
TMP_N1=$(tmpfile dw-test_forward_skip-node-1)
TMP_C0=$(tmpfile dw-test_forward_skip-client)

node_bg -b :7891 &> $TMP_N0
node_bg -b :7892 &> $TMP_N1

client -C 1000 --skip=1,every=2 -F localhost:7892 -C 10ms -n 10 &> $TMP_C0

# even req_id got response times < 10ms, odd ones > 10ms
[ $(grep 'elapsed: .*req_id: [02468]' $TMP_C0 | grep -c 'elapsed: [0-9]\{4\} us') == 5 ]
[ $(grep 'elapsed: .*req_id: [13579]' $TMP_C0 | grep -c 'elapsed: [0-9]\{5\} us') == 5 ]

kill_all SIGINT

rm $TMP_N0
rm $TMP_N1

rm $TMP_C0


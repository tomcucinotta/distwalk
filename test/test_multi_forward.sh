#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

TMP_N0=$(mktemp /tmp/dw-test_multi_forward-0-node-XXX.txt)
TMP_N1=$(mktemp /tmp/dw-test_multi_forward-1-node-XXX.txt)
TMP_N2=$(mktemp /tmp/dw-test_multi_forward-2-node-XXX.txt)

node_bg -b :7891 &> $TMP_N0
node_bg -b :7892 &> $TMP_N1
node_bg -b :7893 &> $TMP_N2

# classic multi-fwd
client -F :7892,:7893 -C 1000 -C 2000 -R | grep -q "Sent pkts - success: 1"
cat $TMP_N1 | grep -q "COMPUTE(1000us)->COMPUTE(2000us)->REPLY(512b)->EOM"
cat $TMP_N2 | grep -q "COMPUTE(1000us)->COMPUTE(2000us)->REPLY(512b)->EOM"

# branched multi-fwd
client -F :7892,branch -C 1111 -F:7893,branch -C 2222 -R | grep -q "Sent pkts - success: 1"
cat $TMP_N1 | grep -q "COMPUTE(1111us)->REPLY(512b)->EOM"
cat $TMP_N2 | grep -q "COMPUTE(2222us)->REPLY(512b)->EOM"

# combined
TMP_N3=$(mktemp /tmp/dw-test_multi_forward-3-node-XXX.txt)
node_bg -b :7894 &> $TMP_N3

client -F :7892,branch -C 2222 -F :7893,:7894,branch -C 3333 -R | grep -q "Sent pkts - success: 1"
cat $TMP_N1 | grep -q "COMPUTE(2222us)->REPLY(512b)->EOM"
cat $TMP_N2 | grep -q "COMPUTE(3333us)->REPLY(512b)->EOM"
cat $TMP_N3 | grep -q "COMPUTE(3333us)->REPLY(512b)->EOM"

# wait fastest path only
tmp_client=$(mktemp /tmp/dw-test_multi_forward-cwait-client-XXX.txt)
client -F :7892,branch,nack=1 -C 5000 -F :7893,:7894,branch -C 1000000 -R > $tmp_client
elapsed=$(cat $tmp_client | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 5000 ] && [ $elapsed -lt 100000 ]
kill_all SIGINT


rm $TMP_N0
rm $TMP_N1
rm $TMP_N2
rm $TMP_N3

rm $tmp_client

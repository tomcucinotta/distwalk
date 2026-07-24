#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

TMP_N0=$(mktemp /tmp/dw-test_forward-10-node-XXX.txt)
TMP_N1=$(mktemp /tmp/dw-test_forward-11-node-XXX.txt)
TMP_C0=$(mktemp /tmp/dw-test_forward-1c0-client-XXX.txt)

node_bg -b :7891 &> $TMP_N0
node_bg -b :7892 &> $TMP_N1

client -C 1000 -F localhost:7892 -C 2000
client -C 1000 -F 127.0.0.1:7892 -C 2000

client --to=tcp://:7891 -C 1000 -F :7892 -C 2000 &> $TMP_C0

kill_all SIGINT

cat $TMP_N0 | grep -q "Forwarding req 0 to 127.0.0.1:7892"
cat $TMP_N0 | grep -q "Handling response to FORWARD from 127.0.0.1:7892"

cat $TMP_N1 | grep -q "Handling REPLY:"

cat $TMP_C0 | grep -q "is over (after receive/skip of pkt 0), closing socket"

rm $TMP_N0
rm $TMP_N1
rm $TMP_C0

# ---

TMP_N0=$(mktemp /tmp/dw-test_forward-20-node-XXX.txt)
TMP_C0=$(mktemp /tmp/dw-test_forward-2c0-client-XXX.txt)

node_bg &> $TMP_N0

# test forwarding to a non-existing client
client -C 1000 -F localhost:7895 -C 2000 &> $TMP_C0 &
sleep 1

kill_all SIGINT
cat $TMP_N0 | grep -q "Connection to remote peer refused, conn_id=2"

rm $TMP_N0
rm $TMP_C0

# ---

TMP_N0=$(mktemp /tmp/dw-test_forward-30-node-XXX.txt)
TMP_N1=$(mktemp /tmp/dw-test_forward-31-node-XXX.txt)
TMP_N2=$(mktemp /tmp/dw-test_forward-32-node-XXX.txt)

node_bg -b :7891 &> $TMP_N0
node_bg -b :7892 &> $TMP_N1
node_bg -b :7893 &> $TMP_N2

# multiple contexes
client -F :7892 -C 1000 -R -F :7893 -C 2000 -R | grep -q "Sent pkts - success: 1"

cat $TMP_N0 | grep -q "Forwarding req 0 to 127.0.0.1:7892"
cat $TMP_N0 | grep -q "Forwarding req 0 to 127.0.0.1:7893"

cat $TMP_N1 | grep -q "COMPUTE(1000us)->REPLY(512b)->EOM"
cat $TMP_N2 | grep -q "COMPUTE(2000us)->REPLY(512b)->EOM"
kill_all SIGINT

rm $TMP_N0
rm $TMP_N1
rm $TMP_N2

# ---

TMP_N0=$(mktemp /tmp/dw-test_forward-40-XXX.txt)
TMP_N1=$(mktemp /tmp/dw-test_forward-41-XXX.txt)
TMP_N2=$(mktemp /tmp/dw-test_forward-42-XXX.txt)

node_bg -b :7891 &> $TMP_N0
node_bg -b :7892 &> $TMP_N1
node_bg -b :7893 &> $TMP_N2

# nested forward
client -F :7892 -C 1000 -F :7893 -C 2000 -C 3000 -R | grep -q "Sent pkts - success: 1"

cat $TMP_N0 | grep -q "Forwarding req 0 to 127.0.0.1:7892"
cat $TMP_N1 | grep -q "Forwarding req 0 to 127.0.0.1:7893"

cat $TMP_N2 | grep -q "COMPUTE(2000us)->COMPUTE(3000us)->REPLY(512b)->EOM"

kill_all SIGINT

rm $TMP_N0
rm $TMP_N1
rm $TMP_N2


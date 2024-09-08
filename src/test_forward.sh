#!/bin/bash

. common.sh

TMP_N0=$(mktemp /tmp/dw-node-fwd-1-XXX.dat)
TMP_N1=$(mktemp /tmp/dw-node-fwd-2-XXX.dat)
TMP_C0=$(mktemp /tmp/dw-client-fwd-XXX.dat)

node_bg -b :7891 &> $TMP_N0
node_bg -b :7892 &> $TMP_N1

client -C 1000 -F localhost:7892 -C 2000
client -C 1000 -F 127.0.0.1:7892 -C 2000

client --to=tcp://:7891 -C 1000 -F :7892 -C 2000 &> $TMP_C0

kill_all SIGINT

cat $TMP_N0 | grep -q "Forwarding req 0 to 127.0.0.1:7892"
cat $TMP_N0 | grep -q "Handling response to FORWARD from 127.0.0.1:7892"

cat $TMP_N1 | grep -q "Handling REPLY:"

cat $TMP_C0 | grep -q "Session is over (after receive of pkt 0), closing socket"

node_bg &> $TMP_N0

client -C 1000 -F localhost:7895 -C 2000 &> $TMP_C0 &
sleep 1

kill_all SIGINT

cat $TMP_N0 | grep -q "FORWARD connection failed, conn_id=1" # old msg: "Connection refused"

rm $TMP_N0
rm $TMP_N1
rm $TMP_C0

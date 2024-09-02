#!/bin/bash

. common.sh

TMP_N0=$(mktemp /tmp/dw-node-fwd-1-XXX.dat)
TMP_C0=$(mktemp /tmp/dw-client-fwd-XXX.dat)

node_bg -b :7891 &> $TMP_N0

client -C 1000 -F localhost -C 2000
client -C 1000 -F 127.0.0.1 -C 2000

client --tcp :7891 -C 1000 -F :7891 -C 2000 &> $TMP_C0

cat $TMP_N0 | grep -q "Forwarding req 0 to 127.0.0.1:7891"
cat $TMP_N0 | grep -q "Handling response to FORWARD from 127.0.0.1:7891"

cat $TMP_N0 | grep -q "Handling REPLY:"

cat $TMP_C0 | grep -q "Session is over (after receive of pkt 0), closing socket"

kill_all SIGINT

rm $TMP_N0
rm $TMP_C0

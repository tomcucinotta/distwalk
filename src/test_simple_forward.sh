#!/bin/bash

. common.sh

TMP0=$(mktemp /tmp/dw-node-fwd-1-XXX.dat)
TMP1=$(mktemp /tmp/dw-node-fwd-2-XXX.dat)
TMP2=$(mktemp /tmp/dw-client-fwd-XXX.dat)

node_bg --tcp 7891 &> $TMP0
node_bg --tcp 7892 &> $TMP1

client --tcp :7891 -C 1000 -F :7892 -C 2000 &> $TMP2


cat $TMP0 | grep -q "Forwarding req 0 to 127.0.0.1:7892"
cat $TMP0 | grep -q "Handling response to FORWARD from 127.0.0.1:7892"

cat $TMP1 | grep -q "Handling REPLY:"

cat $TMP2 | grep -q "Session is over (after receive of pkt 0), closing socket"

rm $TMP0
rm $TMP1
rm $TMP2

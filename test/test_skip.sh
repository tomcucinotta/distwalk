#!/bin/bash

. common.sh

TMP=$(mktemp /tmp/dw-node-skip-XXX.txt)

node_bg &> $TMP

client -C 50 --skip 1 -C 100

grep -q "COMPUTE.50us" $TMP
! grep -q "COMPUTE.100us" $TMP
kill_all SIGINT

#
node_bg &> $TMP

client -C 50 --skip 2 -C 100 -C 150 -C 200

grep -q "COMPUTE.50us" $TMP
! grep -q "COMPUTE.100us" $TMP
! grep -q "COMPUTE.150us" $TMP
grep -q "COMPUTE.200us" $TMP
kill_all SIGINT

#
node_bg &> $TMP

client --skip 1,every=2 -C 100 -C 200 -n 2

grep "COMPUTE....us" $TMP | head -1 | grep -q " COMPUTE(200us)->REPLY"
grep "COMPUTE....us" $TMP | tail -1 | grep -q " COMPUTE(100us)->COMPUTE(200us)->REPLY"

kill_all SIGINT

#
node_bg &> $TMP

client -C 10 --skip 1,prob=0.5 -C 20 -n 100

[ $(grep -c "COMPUTE.10us" $TMP) -eq 100 ]
[ $(grep -c "COMPUTE.20us" $TMP) -lt 59 ]

client -C 15 --skip 1,prob=0.3 -C 25 -n 100

[ $(grep -c "COMPUTE.15us" $TMP) -eq 100 ]
[ $(grep -c "COMPUTE.25us" $TMP) -lt 79 ]
kill_all SIGINT

#
TMP1=$(mktemp /tmp/dw-node1-fwd-skip-XXX.txt)
TMP2=$(mktemp /tmp/dw-node2-fwd-skip-XXX.txt)

node_bg -b :7891 &> $TMP1
node_bg -b :7892 &> $TMP2

client -C 10 --skip 1,prob=0.5 -F :7892 -C 20 -n 100

[ $(grep -c "COMPUTE.10us" $TMP1) -eq 100 ]
[ $(grep -c "COMPUTE.20us" $TMP2) -lt 59 ]
kill_all SIGINT

#
TMP1=$(mktemp /tmp/dw-node1-fwd-fwd-skip-XXX.txt)
TMP2=$(mktemp /tmp/dw-node2-fwd-fwd-skip-XXX.txt)
TMP3=$(mktemp /tmp/dw-node3-fwd-fwd-skip-XXX.txt)

node_bg -b :7891 &> $TMP1
node_bg -b :7892 &> $TMP2
node_bg -b :7893 &> $TMP3

client -C 10 -F :7892 -C 20 --skip 1,prob=0.5 -F :7893 -C 30 -n 100

[ $(grep -c "COMPUTE.10us" $TMP1) -eq 100 ]
[ $(grep -c "COMPUTE.20us" $TMP2) -eq 100 ]
[ $(grep -c "COMPUTE.30us" $TMP3) -lt 59 ]
kill_all SIGINT

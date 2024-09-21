#!/bin/bash

. common.sh

TMP=$(mktemp /tmp/dw-node-skip-XXX.dat)

node_bg &> $TMP

client -C 500 --skip 1 -C 1000

grep -q "COMPUTE.500us" $TMP
grep -q "COMPUTE.1000us" $TMP || true

kill_all SIGINT

node_bg &> $TMP

client -C 500 --skip 2 -C 1000 -C 1500 -C 2000

grep -q "COMPUTE.500us" $TMP
grep -q "COMPUTE.1000us" $TMP || true
grep -q "COMPUTE.1500us" $TMP || true
grep -q "COMPUTE.2000us" $TMP

kill_all SIGINT

node_bg &> $TMP

client -C 10 --skip 1,prob=0.5 -C 20 -n 100

[ $(grep -c "COMPUTE.10us" $TMP) -eq 100 ]
[ $(grep -c "COMPUTE.20us" $TMP) -lt 59 ]

client -C 15 --skip 1,prob=0.3 -C 25 -n 100

[ $(grep -c "COMPUTE.15us" $TMP) -eq 100 ]
[ $(grep -c "COMPUTE.25us" $TMP) -lt 79 ]

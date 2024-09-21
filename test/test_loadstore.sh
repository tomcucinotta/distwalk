#!/bin/bash

. common.sh

TMP=$(mktemp /tmp/dw-store-XXX.dat)

node_bg -s $TMP
client -S 65536
[ $(du -b $TMP | cut -f1) -eq 65536 ]

kill_all SIGINT

strace_node_bg -s $TMP --sync=100 > /tmp/dw-log.txt 2>&1
sleep 1

kill_all SIGINT

[ $(grep fsync /tmp/dw-log.txt | wc -l) -ge 10 ]

rm /tmp/dw-log.txt

rm $TMP

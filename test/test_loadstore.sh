#!/bin/bash

. common.sh

TMP=$(mktemp /tmp/dw-store-XXX.txt)
trace_log=/tmp/dw-log.txt

node_bg -s $TMP
client -S 32000000
[ $(du -b $TMP | cut -f1) -eq 32000000 ]

client -L 1024
client -L unif:min=1024,max=2048
client --load-offset 0 -L 1024
client --load-offset unif:min=0,max=3072 -L 1024

kill_all SIGKILL

strace_node_bg -s $TMP &> $trace_log
client --store-offset 17 -S 65536
grep -e " 17, SEEK_SET" $trace_log

client --store-offset 31 -S 65536
grep -e " 31, SEEK_SET" $trace_log

kill_all SIGINT

strace_node_bg -s $TMP --sync=100 > $trace_log 2>&1
sleep 1

kill_all SIGINT

[ $(grep -c fsync $trace_log) -ge 10 ]

rm $trace_log

rm $TMP

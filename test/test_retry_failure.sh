#!/bin/bash

. common.sh

tmp=$(mktemp /tmp/test_retry_failure-XXX.txt)

client_bg --to=tcp://127.0.0.1:7894 --retry-num 2 --retry-period 200 &> $tmp

sleep 2
node_bg -b :7894

cat $tmp
cat $tmp | grep -q "Connection to 127.0.0.1:7894 failed:"

#!/bin/bash

. common.sh

tmp=$(mktemp /tmp/test_retry_success-XXX.dat)

client_bg --to=tcp://127.0.0.1:7894 --retry-num 10 --retry-period 1000 &> $tmp

sleep 2
node_bg -b :7894

sleep 1

grep -q "CONN allocated" $tmp

rm $tmp

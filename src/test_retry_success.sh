#!/bin/bash

. common.sh

tmp=$(mktemp /tmp/test_retry_success-XXX.dat)

client_bg --tcp=127.0.0.1:7894 --retry-num 10 --retry-period 1000 &> $tmp

sleep 2
node_bg --tcp=7894

cat $tmp
cat $tmp | grep -q "CONN allocated"

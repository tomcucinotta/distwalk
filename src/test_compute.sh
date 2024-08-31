#!/bin/bash

. common.sh

TMP=$(mktemp /tmp/test_compute-XXX.dat)

node_bg &> $TMP
elapsed=$(client --cl :8000 -C 10000 | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 10000 ] && [ $elapsed -lt 20000 ]
elapsed=$(client --cl :8001 -C 10000 -C 20000 | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 30000 ] && [ $elapsed -lt 40000 ]

cat $TMP | grep -q "Accepted connection from: 127.0.0.1:8000"
cat $TMP | grep -q "Accepted connection from: 127.0.0.1:8001"
rm $TMP

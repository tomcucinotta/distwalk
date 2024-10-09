#!/bin/bash

. common.sh

TMP=$(mktemp /tmp/dw-store-XXX.dat)

node_bg -s $TMP --odirect
client -S 33554432
[ $(du -b $TMP | cut -f1) -eq 33554432 ]

client -L 33554432

rm $TMP

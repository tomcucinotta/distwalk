#!/bin/bash

. common.sh

TMP=$(mktemp /tmp/dw-store-XXX.dat)

node_bg -s $TMP
client -S 65536
[ $(du -b $TMP | cut -f1) -eq 65536 ]

client -L 65536

rm $TMP

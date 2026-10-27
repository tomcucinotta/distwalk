#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

TMP=$(tmpfile dw-test_loadstore_odirect)

node_bg -s $TMP --odirect
client -S 33554432
[ $(du -b $TMP | cut -f1) -eq 33554432 ]

client -L 33554432

rm $TMP

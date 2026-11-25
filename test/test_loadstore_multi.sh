#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

TMP0=$(tmpfile dw-test_loadstore_multi-0)
TMP1=$(tmpfile dw-test_loadstore_multi-1)

size() { du -b "$1" | cut -f1; }

node -s $TMP0 -s $TMP1 &
sleep 1

client -S size=[20000000],dev=0
client -S size=[40000000],dev=1

[ $(size $TMP0) -eq 20000000 ]
[ $(size $TMP1) -eq 40000000 ]

client -S size=[5000000],dev=0
[ $(size $TMP0) -eq 25000000 ]
[ $(size $TMP1) -eq 40000000 ]

client -S size=[3000000],dev=1
[ $(size $TMP0) -eq 25000000 ]
[ $(size $TMP1) -eq 43000000 ]

client -S size=[1000000],dev=0 -S size=[2000000],dev=1
[ $(size $TMP0) -eq 26000000 ]
[ $(size $TMP1) -eq 45000000 ]

kill_all SIGINT

rm $TMP0 $TMP1

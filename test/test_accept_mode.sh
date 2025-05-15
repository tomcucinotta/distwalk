#!/bin/bash

. common.sh

## check syntax

node_bg -a child
kill_all SIGINT
node_bg --accept-mode child
kill_all SIGINT
node_bg -a parent
kill_all SIGINT
node_bg --accept-mode parent
kill_all SIGINT
node_bg -a shared
kill_all SIGINT
node_bg --accept-mode shared
kill_all SIGINT

! node_bg -a xxx --num-threads=2
! node_bg --accept-mode xxx --num-threads=2
! node_bg -a child1 --num-threads=2
! node_bg -a parent1 --num-threads=2

## check with netstat

node_bg --wait-bind-num 2 -a child --num-threads=2
[ $(netstat --inet -an | awk '$6 != "TIME_WAIT"' | grep -c 7891) -eq 2 ]

kill_all SIGINT

node_bg -a parent --num-threads=2
[ $(netstat --inet -an | awk '$6 != "TIME_WAIT"' | grep -c 7891) -eq 1 ]

kill_all SIGINT

node_bg -a shared --num-threads=2
[ $(netstat --inet -an | awk '$6 != "TIME_WAIT"' | grep -c 7891) -eq 1 ]

kill_all SIGINT

tmp=/tmp/dw-log.txt

## check calls to listen() and bind() with strace

strace_node_bg --wait-bind-num 2 -a child --num-threads=2 > $tmp 2>&1
[ $(grep -c listen $tmp) -eq 2 ] && [ $(grep -c bind $tmp) -eq 2 ]

kill_all SIGINT

strace_node_bg -a parent --num-threads=2 > $tmp 2>&1
[ $(grep -c listen $tmp) -eq 1 ] && [ $(grep -c bind $tmp) -eq 1 ]

kill_all SIGINT

strace_node_bg -a shared --num-threads=2 > $tmp 2>&1
[ $(grep -c listen $tmp) -eq 1 ] && [ $(grep -c bind $tmp) -eq 1 ]

kill_all SIGINT

rm $tmp

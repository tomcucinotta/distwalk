#!/bin/bash

. common.sh

## check with netstat

node_bg -a child --num-threads=2
[ $(netstat --inet -an | grep -c 7891) -eq 2 ]

kill_all SIGINT

node_bg -a parent --num-threads=2
[ $(netstat --inet -an | grep -c 7891) -eq 1 ]

kill_all SIGINT

node_bg -a shared --num-threads=2
[ $(netstat --inet -an | grep -c 7891) -eq 1 ]

tmp=/tmp/dw-log.txt

kill_all SIGINT

## check calls to listen() and bind() with strace

strace_node_bg -a child --num-threads=2 > $tmp 2>&1
[ $(grep -c listen $tmp) -eq 2 ] && [ $(grep -c bind $tmp) -eq 2 ]

kill_all SIGINT

strace_node_bg -a parent --num-threads=2 > $tmp 2>&1
[ $(grep -c listen $tmp) -eq 1 ] && [ $(grep -c bind $tmp) -eq 1 ]

kill_all SIGINT

strace_node_bg -a shared --num-threads=2 > $tmp 2>&1
[ $(grep -c listen $tmp) -eq 1 ] && [ $(grep -c bind $tmp) -eq 1 ]

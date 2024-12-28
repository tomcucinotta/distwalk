#!/bin/bash

. common.sh

## check syntax

node_bg -p select
kill_all SIGINT
node_bg --poll-mode select
kill_all SIGINT

node_bg -p poll
kill_all SIGINT
node_bg --poll-mode poll
kill_all SIGINT

node_bg -p epoll
kill_all SIGINT
node_bg --poll-mode epoll
kill_all SIGINT

! node_bg -p xxx
! node_bg --poll-mode xxx
! node_bg -p select1
! node_bg --poll-mode poll1

tmp=/tmp/dw-log.txt

## check calls to select(), poll() and epoll_ctl() with strace

strace_node_bg -p select > $tmp 2>&1
client -C 10ms -n 1
grep select $tmp && [ $(grep -c " poll" $tmp) -eq 0 ]
kill_all SIGINT

strace_node_bg -p poll > $tmp 2>&1
client -C 10ms -n 1
grep " poll" $tmp && [ $(grep -c epoll $tmp) -eq 0 ] && [ $(grep -c select $tmp) -eq 0 ]
kill_all SIGINT

strace_node_bg -p epoll > $tmp 2>&1
client -C 10ms -n 1
grep epoll $tmp && [ $(grep -c " poll" $tmp) -eq 0 ] && [ $(grep -c select $tmp) -eq 0 ]
kill_all SIGINT

rm $tmp

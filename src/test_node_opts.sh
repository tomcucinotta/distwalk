#!/bin/bash

. common.sh

node_bg
[ $(ps H -o 'pid tid cmd comm' | grep connw | grep -v grep | wc -l) -eq 1 ]

kill_all SIGINT

node_bg --num-threads=2
[ $(ps H -o 'pid tid cmd comm' | grep connw | grep -v grep | wc -l) -eq 2 ]

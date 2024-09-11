#!/bin/bash

. common.sh

node_bg

client -C 500 -n 100 -r 1 --ramp-step-secs=1 --ramp-delta-rate=1 --ramp-num-steps=10
client -C 500 -n 100 -r 1 --ramp-filename=<(echo -e "1\n2\n3\n4\n5\n6\n7\n8\n9\n10")

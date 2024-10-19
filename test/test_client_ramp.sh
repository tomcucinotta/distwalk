#!/bin/bash

. common.sh

node_bg

client -C 500 -n 100 -r seq:min=1,max=10 --rate-step-secs=1
client -C 500 -n auto -r seq:min=1,max=10 --rate-step-secs=1
client -C 500 -n 100 -r file:<(echo -e "1\n2\n3\n4\n5\n6\n7\n8\n9\n10") --rate-step-secs=1
client -C 500 -n auto -r file:<(echo -e "1\n2\n3\n4\n5\n6\n7\n8\n9\n10") --rate-step-secs=1

#!/bin/bash

. common.sh

node_bg
client -f <(echo "
--send-pkt-size 256
-n 10
-C 10000
--resp-pkt-size 1024")

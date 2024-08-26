#!/bin/bash

. common.sh

node_bg --udp=7891 &
client --udp=127.0.0.1:7891
client --udp=127.0.0.1:7891 -n 10
client --udp=127.0.0.1:7891 -C 10000

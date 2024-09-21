#!/bin/bash

. common.sh

node_bg -b udp://:7891 &
client --to=udp://127.0.0.1:7891
client --to=udp://127.0.0.1:7891 -n 10
client --to=udp://127.0.0.1:7891 -C 10000

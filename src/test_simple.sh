#!/bin/bash

. common.sh

node --help
client --help

node_bg &
client
client -n 10
client -C 10000

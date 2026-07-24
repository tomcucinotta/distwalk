#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

node --help
client --help

node -h
client -h

node --usage
client --usage

node_bg
client
client -n 10
client -C 10000

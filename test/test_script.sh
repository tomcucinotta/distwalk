#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

node_bg
client -f <(echo "
--ps 256
-n 10
-C 10000
--rs=1024")

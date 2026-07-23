#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

kill_all "$@"

sleep 1
echo "end of kill_all"


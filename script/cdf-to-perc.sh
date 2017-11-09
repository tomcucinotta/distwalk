#!/bin/sh

p=99.0

if [ "$1" = "-p" ]; then
    p=$2
    shift
    shift
fi

awk '{ if ($2 >= '$p') { print $1; exit; } }' "$1"

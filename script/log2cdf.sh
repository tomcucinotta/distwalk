#!/bin/bash

tmp=$(mktemp /tmp/temp-cdf-file-XXX.dat)

cat $1 | grep "t: " | grep "elapsed: " > $tmp

lines=$(wc -l $tmp | cut -d ' ' -f 1)
cat $tmp | cut -d ' ' -f 5 | sort -n | awk "{ print \$1,NR/$lines; }"

rm $tmp

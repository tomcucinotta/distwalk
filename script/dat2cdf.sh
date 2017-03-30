#!/bin/bash

tmp=$(tempfile)

cat $1 > $tmp

lines=$(wc -l $tmp | cut -d ' ' -f 1)
cat $tmp | cut -d ' ' -f 2 | sort -n | awk "{ print \$1,NR/$lines; }"

rm $tmp

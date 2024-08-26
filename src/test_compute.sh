#!/bin/bash

. common.sh

node_bg
client -C 10000
elapsed=$(client -C 10000 | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 10000 ] && [ $elapsed -lt 20000 ]
elapsed=$(client -C 10000 -C 20000 | grep 'elapsed:' | sed -e 's/.*elapsed: //; s/ us.*//')
[ $elapsed -gt 30000 ] && [ $elapsed -lt 40000 ]

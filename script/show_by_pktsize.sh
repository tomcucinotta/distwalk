#!/bin/bash

for s in 128 256 512 1024; do echo $s $(../../script/log2dat.sh log-t600-s$s-c540.txt | cut -d ' ' -f 2 | datastat); done

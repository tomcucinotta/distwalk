#!/bin/bash

. common.sh

run test_distrib_debug -h
run test_distrib_debug --help
run test_distrib_debug -d 20
run test_distrib_debug -d 20 -n 10

run test_distrib_debug -d 15k
run test_distrib_debug -d 15K
run test_distrib_debug -d 15m
run test_distrib_debug -d 15M
run test_distrib_debug -d 15g
run test_distrib_debug -d 15G

for dist in unif:min=20,max=40 exp:20 exp:20,min=10,max=40 norm:20,std=5 norm:20,std=5,min=10,max=40 lognorm:3,std=1 lognorm:xavg=3,xstd=1 gamma:20,k=1,scale=2 gamma:20,k=2,scale=2 aseq:1000,max=2000 aseq:min=1000,max=2000,step=250 gseq:1,max=16 gseq:min=1,max=16,step=2; do
    run test_distrib_debug -d $dist
done

tmp=$(mktemp /tmp/samples-XXX.txt)
echo -e "10\n20\n30\n" > $tmp
run test_distrib_debug -d file:$tmp
rm $tmp

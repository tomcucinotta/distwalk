#!/bin/bash

. common.sh

run test_distrib_debug -h
run test_distrib_debug --help
run test_distrib_debug -d 20
run test_distrib_debug -d 20 -n 10

for dist in unif:min=20,max=40 exp:20 exp:20,min=10,max=40 norm:20,std=5 norm:20,std=5,min=10,max=40 gamma:20,k=1,scale=2 gamma:20,k=2,scale=2 seq:min=1000,max=2000 seq:min=1000,max=2000,step=250; do
    run test_distrib_debug -d $dist
done

tmp=$(mktemp /tmp/samples-XXX.dat)
echo -e "10\n20\n30\n" > $tmp
run test_distrib_debug -d file:$tmp
rm $tmp

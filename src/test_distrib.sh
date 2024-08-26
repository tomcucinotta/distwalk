#!/bin/bash

. common.sh

./test_distrib_debug -h
./test_distrib_debug --help
./test_distrib_debug -d 20
./test_distrib_debug -d 20 -n 10

for dist in unif:min=20,max=40 exp:20 exp:20,min=10,max=40 norm:20,std=5 norm:20,std=5,min=10,max=40 gamma:20,k=1,scale=2 gamma:20,k=2,scale=2; do
    ./test_distrib_debug -d $dist
done

tmp=$(mktemp /tmp/samples-XXX.dat)
echo -e "10\n20\n30\n" > $tmp
./test_distrib_debug -d file:$tmp
rm $tmp

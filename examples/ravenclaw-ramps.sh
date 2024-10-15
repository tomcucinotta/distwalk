#!/bin/bash

kill `pidof dw_node` &> /dev/null
kill `pidof dw_node_debug` &> /dev/null
kill `pidof dw_node_tsan` &> /dev/null

set -x
../src/dw_node -b :7892 --nt 10 -c 5,7,9,11,13,15,17,19,21,23 &
nodepid=$!
sleep 1


sudo ../script/cpu-setup.sh > /dev/null
for i in 14 12 10 8 6 4 2; do 
    echo $i 
    ../src/dw_client --to :7892 -C 10000 -n 1000 -r aseq:min=2,max=1000,step=$i --rate-step-secs=1 &> aseq_min2_max1000_step$(printf "%02d" $i)_secs1.log
done

for i in 8 7 6 5 4 3 2; do
    echo $i
    ../src/dw_client --to :7892 -C 10000 -n 1000 -r gseq:min=2,max=1000,step=$i --rate-step-secs=1 &> gseq_min2_max1000_step$(printf "%02d" $i)_secs1.log
done
sudo ../script/cpu-teardown.sh > /dev/null

for fname in ./*.log; do
    ../script/log2csv.sh $fname > ${fname/.log/.csv}
done

kill $nodepid &> /dev/null

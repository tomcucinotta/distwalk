#!/bin/bash

kill `pidof dw_node` &> /dev/null
kill `pidof dw_node_debug` &> /dev/null
kill `pidof dw_node_tsan` &> /dev/null

set -x

sudo ../script/cpu-setup.sh > /dev/null
for am in parent child shared; do
for i in 10 8 4 2 1; do
    echo $i
    ../src/dw_node -b :7892 --accept-mode $am --nt $i -c 5,7,9,11,13,15,17,19,21,23,25 &
    nodepid=$!
    while ! nc -z localhost 7892; do sleep 1; done

    taskset -c 4,6,8,10,12,14,16,18 ../src/dw_client --to :7892 -C 100 -n auto -r aseq:min=1,max=100,step=2 --rate-step-secs=2 --ns 6000 --nt 1 &> ravenclaw_horizontal_scaling_nt$(printf "%02d" $i)_am$am.log

    ../script/ctx-switches.sh $nodepid &> ravenclaw_horizontal_scalingctx_switches_nt$(printf "%02d" $i)_am$am.csv
    kill $nodepid &> /dev/null
    while nc -z localhost 7892; do sleep 1; done
done
done
sudo ../script/cpu-teardown.sh > /dev/null


for fname in ./*.log; do
    ../script/log2csv.sh $fname > ${fname/.log/.csv}
done

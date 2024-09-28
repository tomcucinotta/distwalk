#!/bin/bash

kill `pidof dw_node` &> /dev/null
kill `pidof dw_node_debug` &> /dev/null
kill `pidof dw_node_tsan` &> /dev/null

# Input args
if [ -z "$1" ]; then
    echo "Usage: $0 </path/to/storage/file.data> [rate]"
    exit -1
fi
STORAGE_PATH=$1

if [ ! -f $STORAGE_PATH ]; then
    touch $STORAGE_PATH
fi

OPT_RATE=
OPT_RATE_STR=""
if [ ! -z "$2" ]; then
    OPT_RATE="-r $2"
    OPT_RATE_STR=$(printf "_r%03d" $2)
fi

# Detect if storate file resides on a rotational disk or not
disk_partition=$(df -P $STORAGE_PATH | awk 'END{print $1}')
is_rotational=$(lsblk -lpn -o name,rota | grep $disk_partition | awk '{print $2}')

disk_type=
if [ "$is_rotational" -eq 1 ]; then
    disk_type="hdd"
else
    disk_type="ssd"
fi

# log files
nosync_log=$(mktemp /tmp/disk-rand-write-nosync-$disk_type$OPT_RATE_STR-XXX.log)
sync_log=${nosync_log/nosync/sync}

sudo ../script/cpu-setup.sh > /dev/null

../src/dw_node -s $STORAGE_PATH --thread-affinity 2,3 &
nodepid=$!
sleep 1


taskset -c 0,1 ../src/dw_client --store-offset unif:min=0,max=1000000 -S 1000,nosync -n 300 $OPT_RATE &> $nosync_log 
taskset -c 0,1 ../src/dw_client --store-offset unif:min=0,max=1000000 -S 1000,sync -n 300 $OPT_RATE &> $sync_log
kill $nodepid &> /dev/null


psync_nowait_log=${nosync_log/nosync/psync100nowait}
psync_wait_log=${nosync_log/nosync/psync100wait}

../src/dw_node -s $STORAGE_PATH --sync 100 --thread-affinity 2,3 &
nodepid=$!
sleep 1

taskset -c 0,1 ../src/dw_client --store-offset unif:min=0,max=1000000 -S 1000,nosync -n 400 $OPT_RATE &> $psync_nowait_log
taskset -c 0,1 ../src/dw_client --store-offset unif:min=0,max=1000000 -S 1000,sync -n 400 $OPT_RATE &> $psync_wait_log
kill $nodepid &> /dev/null
sudo ../script/cpu-teardown.sh > /dev/null

for fname in $nosync_log $sync_log $psync_nowait_log $psync_wait_log; do
    ../script/log2csv.sh $fname > ${fname/.log/.csv}
done

echo "Results in:"
printf "\t$nosync_log\n\t$sync_log\n\t$psync_nowait_log\n\t$psync_wait_log\n"

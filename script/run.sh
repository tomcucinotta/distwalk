#!/bin/bash

echo() {
    /bin/echo $(date +%H.%M.%S): "$@"
}

echo "Starting on $(date) @ $(hostname) - $(uname -r)"

PKTS=10000
CPUS="0"
CPUL=$(/bin/echo $CPUS | sed -e 's/ /,/g')
CLIENT=balsini.retis
SERVER=$(hostname)

# sleep-time between exps rounds
PAUSE=0

# Check whether any of the selected $CPUS share the same core_id
# (possible with hyper-threading, very likely leads to bad results)
for c1 in $CPUS; do
    for c2 in $CPUS; do
	if [ "$c1" = "$c2" ]; then
	    continue;
	fi
	core1=$(cat /sys/devices/system/cpu/cpu$c1/topology/core_id)
	core2=$(cat /sys/devices/system/cpu/cpu$c2/topology/core_id)
	if [ "$core1" = "$core2" ]; then
	    echo "ERROR: using CPUs $c1,$c2 in same core: $core1==$core2!"
	    exit -1
	fi
    done
done

killall client node
killall client_debug node_debug

echo "Synchronizing software with client machine $CLIENT..."
rsync -avz -e ssh --exclude=.git --exclude='log*.txt' ../ $CLIENT:cloudwalk/

echo "Looping over configurations..."

for PS in 128 256 512 1024 2048 4096; do
    for DT in 600 700 800 900 1000; do
	for BW in 0.5 0.6 0.7 0.8 0.9; do
	    # Round bc output
	    CT=$(/bin/echo "$DT * $BW" | bc -l | sed -e 's/\..*//')

	    echo ""
	    echo "Trying with PS=$PS, BW=$BW, DT=$DT, CT=$CT"
	    echo ""

	    if [ -f log-t$DT-s$PS-c$CT.txt ]; then
		echo "Skipping because of already existing file: log-t$DT-s$PS-c$CT.txt"
		continue;
	    fi

	    echo "Starting server constrained on CPUs $CPUL..."
	    taskset -c $CPUL ../src/node &

	    echo "Launching client ..."
	    ssh $CLIENT "echo logged && cloudwalk/src/client -s $SERVER -c $PKTS -p $DT -ea -ps $PS -C $CT -ec > log.txt"

	    echo "Client done, copying log.txt..."
	    scp $CLIENT:log.txt log-t$DT-s$PS-c$CT.txt

	    echo "Killing node..."
	    killall node node_debug

	    echo "Waiting for node to die"
	    wait

	done
	echo "Sleeping for $PAUSE secs..."
	sleep $PAUSE
    done
done

echo "Done, quitting."

#!/bin/bash

if [ "$1" = "" ]; then
    echo "Usage: $0 <space-separated cpu list>"
    exit -1
fi

# Check whether any of the selected CPUS in "$1" share the same core_id
# (possible with hyper-threading, very likely leads to bad results)
for c1 in $1; do
    for c2 in $1; do
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

exit 0

#!/bin/bash

if grep -i ubuntu /etc/os-release > /dev/null; then
    for c in $(seq 0 $[ $(grep -c processor /proc/cpuinfo) - 1 ] ); do
	cpufreq-set -c $c -g performance;
    done
elif grep -i fedora /etc/os-release > /dev/null; then
    cpupower -c all frequency-set --governor performance;
fi

if [ -d /sys/devices/system/cpu/intel_pstate ]; then
    echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
fi

# Show status
if grep -i ubuntu /etc/os-release > /dev/null; then
    cpufreq-info
elif grep -i fedora /etc/os-release > /dev/null; then
    cpupower -c all frequency-info
fi

#!/bin/bash

# Disable autogrouping
echo 0 > /proc/sys/kernel/sched_autogroup_enabled

# Block cpu freq
echo 70 > /sys/devices/system/cpu/intel_pstate/max_perf_pct
echo 70 > /sys/devices/system/cpu/intel_pstate/min_perf_pct

if grep -i ubuntu /etc/os-release > /dev/null; then
    for c in $(seq 0 $[ $(grep -c processor /proc/cpuinfo) - 1 ] ); do
	cpufreq-set -c $c -g performance;
    done
elif grep -i fedora /etc/os-release > /dev/null; then
    cpupower -c all frequency-set --governor performance;
fi

for c in $(ls -d /sys/devices/system/cpu/cpu[0-9]*);
do
	if [ -f $c/power/energy_perf_bias ]; then    
		echo "performance" > $c/power/energy_perf_bias
	fi
done

if [ -d /sys/devices/system/cpu/intel_pstate ]; then
	# Disable turbo boost
	echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
	
	if [ -f /sys/devices/system/cpu/intel_pstate/hwp_dynamic_boost ]; then
		# Disable hwp dynamic boost
		echo 0 > /sys/devices/system/cpu/intel_pstate/hwp_dynamic_boost
	fi
fi

# Disable cpu deep idle states
echo 1 | sudo tee /sys/devices/system/cpu/cpu*/cpuidle/state*/disable

# Show status
if grep -i ubuntu /etc/os-release > /dev/null; then
    cpufreq-info
elif grep -i fedora /etc/os-release > /dev/null; then
    cpupower -c all frequency-info
fi

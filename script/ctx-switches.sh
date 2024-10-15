#!/bin/bash


if [ -z "$1" ]; then
    echo "Usage: $0 <pid>"
    exit -1
fi
PID=$1

#awk '/^Name:|^voluntary_ctxt_switches:|^nonvoluntary_ctxt_switches:/ { printf "%s %s, ", $1,$2 }' /proc/$PID/task/*/status
awk '/^Name:/ { if (NR > 1) printf "\n"; printf "%s %s, ", $1, $2 } /^voluntary_ctxt_switches:/ { printf "%s %s, ", $1, $2 } /^nonvoluntary_ctxt_switches:/ { printf "%s %s, ", $1, $2 }' /proc/$PID/task/*/status


exit 0
echo "Name,Tid,Voluntary-ctx-switches,Non-voluntary-ctx-switches"
for tid in `ls /proc/$PID/task/`; do
    name=$(awk '/^Name:/ { print $2 }' /proc/$PID/task/$tid/status)
    voluntary=$(awk '/^voluntary_ctxt_switches:/ { print $2 }' /proc/$PID/task/$tid/status)
    nonvoluntary=$(awk '/^nonvoluntary_ctxt_switches:/ { print $2 }' /proc/$PID/task/$tid/status)
    echo $name,$tid,$voluntary,$nonvoluntary
done

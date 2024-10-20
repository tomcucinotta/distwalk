#!/bin/bash


if [ -z "$1" ]; then
    echo "Usage: $0 <pid>"
    exit -1
fi
PID=$1


echo "Name,Tid,Voluntary-ctx-switches,Non-voluntary-ctx-switches"
for tid in `ls /proc/$PID/task/`; do
    name=$(awk '/^Name:/ { print $2 }' /proc/$PID/task/$tid/status)
    voluntary=$(awk '/^voluntary_ctxt_switches:/ { print $2 }' /proc/$PID/task/$tid/status)
    nonvoluntary=$(awk '/^nonvoluntary_ctxt_switches:/ { print $2 }' /proc/$PID/task/$tid/status)
    echo $name,$tid,$voluntary,$nonvoluntary
done

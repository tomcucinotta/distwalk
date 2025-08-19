#!/bin/bash

# Setup an ipvs-based load balancer using 127.0.0.1:7891 as entrypoint

USAGE="USAGE: sudo $0 [rr|wrr|lc|wlc|lblc|lblcr|dh|sh|sed|nq|fo|ovf|mh]"
if [ "$(whoami)" != "root" ]; then
    echo $USAGE
    exit 1
fi

LB=rr
if [ -n "$1" ]; then
    LB=$1
fi

sudo ipvsadm -D -t 127.0.0.1:7891 &> /dev/null
sudo ipvsadm -A -t 127.0.0.1:7891 -s $LB
[ $? -eq 0 ] || { echo $USAGE; exit 1; }

sudo ipvsadm -a -t 127.0.0.1:7891 -r 127.0.0.1:7892 -m
sudo ipvsadm -a -t 127.0.0.1:7891 -r 127.0.0.1:7893 -m

sudo ipvsadm -l

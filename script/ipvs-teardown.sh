#!/bin/bash

# Teardown an ipvs-based load balancer using 127.0.0.1:7891 as entrypoint

USAGE="USAGE: sudo $0"
if [ "$(whoami)" != "root" ]; then
    echo $USAGE
    exit 1
fi

sudo ipvsadm -D -t 127.0.0.1:7891 &> /dev/null
sudo ipvsadm -l

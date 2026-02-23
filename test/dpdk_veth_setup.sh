#!/bin/bash
# Sets up an amount of veths specified by the (optional) parameter N and interconnects them via a bridge

set -e

N=${1:-4}
BRIDGE=dw_br

ip link add $BRIDGE type bridge
ip link set $BRIDGE up

for i in $(seq 0 $((N - 1))); do
    ip link add dw_veth${i} type veth peer name dw_veth${i}_br
    ip link set dw_veth${i} up
    ip link set dw_veth${i}_br up
    ip link set dw_veth${i}_br master $BRIDGE
done

sleep 2

for i in $(seq 0 $((N - 1))); do
    echo "dw_veth${i} $(cat /sys/class/net/dw_veth${i}/address)"
done

#!/bin/bash
# Destroys the specified number of veths and the bridge
N=${1:-4}
BRIDGE=dw_br

for i in $(seq 0 $((N - 1))); do
    ip link del dw_veth${i} 2>/dev/null || true
done

ip link del $BRIDGE 2>/dev/null || true

#!/bin/bash
# Hybrid test: client -> node1 (DPDK) -> node2/node3 (TCP and/or DPDK)

. common.sh
. dpdk_common.sh

dpdk_check_root
dpdk_check_binary
dpdk_auto_setup 3
trap dpdk_auto_teardown EXIT

NODE1_OPT="-b dpdk://${DPDK_IFACE[0]} -c 0"
CLIENT_OPT="-b dpdk://${DPDK_IFACE[1]} --to dpdk://${DPDK_MAC[0]} --dpdk-rx-cpu 1 --dpdk-tx-cpu 2"

TMP_CLIENT=$(mktemp /tmp/dw-dpdk-client-XXX.txt)

echo "--- forward: DPDK -> TCP ---"

run dw_node_debug $NODE1_OPT &> /dev/null &
run dw_node_debug -b :7892 &> /dev/null &
sleep 2

# forward: client -DPDK-> node1 -TCP-> node2
run dw_client_debug $CLIENT_OPT -n 50 -F localhost:7892 -C 100 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

# pre-compute on node1, forward to node2, post-compute on node1
run dw_client_debug $CLIENT_OPT -n 50 -C 50 -F localhost:7892 -C 100 -R -C 50 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

echo "--- nested forward: DPDK -> TCP -> TCP ---"

# nested: client -DPDK-> node1 -TCP-> node2 -TCP-> node3
run dw_node_debug -b :7893 &> /dev/null &
sleep 1
run dw_client_debug $CLIENT_OPT -n 20 -F localhost:7892 -F localhost:7893 -C 100 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 20" $TMP_CLIENT

echo "--- multi-forward: DPDK + TCP ---"

# multi-forward: node1 forwards to node2 (DPDK) and node3 (TCP)
kill_all
sleep 1

run dw_node_debug $NODE1_OPT &> /dev/null &
run dw_node_debug -b dpdk://${DPDK_IFACE[2]} -c 3 &> /dev/null &
run dw_node_debug -b :7893 &> /dev/null &
sleep 2

run dw_client_debug $CLIENT_OPT -n 20 -C 0 -F dpdk://${DPDK_MAC[2]},localhost:7893 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 20" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 20 -C 0 -F dpdk://${DPDK_MAC[2]},localhost:7893,nack=1 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 20" $TMP_CLIENT

rm -f $TMP_CLIENT
kill_all

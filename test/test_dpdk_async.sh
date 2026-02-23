#!/bin/bash
# Test async DPDK operations: store, load, and DPDK-to-DPDK forward chains

. common.sh
. dpdk_common.sh

dpdk_check_root
dpdk_check_binary
dpdk_auto_setup 4
trap dpdk_auto_teardown EXIT

NODE1_OPT="-b dpdk://${DPDK_IFACE[0]} -c 0"
NODE2_OPT="-b dpdk://${DPDK_IFACE[2]} -c 3"
NODE3_OPT="-b dpdk://${DPDK_IFACE[3]} -c 4"
CLIENT_OPT="-b dpdk://${DPDK_IFACE[1]} --to dpdk://${DPDK_MAC[0]} --dpdk-rx-cpu 1 --dpdk-tx-cpu 2"

TMP_STORE=$(mktemp /tmp/dw-dpdk-store-XXX.txt)
TMP_CLIENT=$(mktemp /tmp/dw-dpdk-client-XXX.txt)

echo "--- store/load over DPDK ---"

run dw_node_debug $NODE1_OPT -s $TMP_STORE &> /dev/null &
sleep 2

run dw_client_debug $CLIENT_OPT -n 1 -S 32768 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 1" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 1 -L 1024 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 1" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 1 -S 4096 -L 1024 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 1" $TMP_CLIENT

kill_all SIGKILL
sleep 1

echo "--- simple forward: DPDK -> DPDK ---"

run dw_node_debug $NODE1_OPT &> /dev/null &
run dw_node_debug $NODE2_OPT &> /dev/null &
sleep 2

run dw_client_debug $CLIENT_OPT -n 10 -F dpdk://${DPDK_MAC[2]} -C 100 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 10" $TMP_CLIENT

kill_all SIGINT
sleep 1

echo "--- nested, multi-forward and branched ---"

run dw_node_debug $NODE1_OPT &> /dev/null &
run dw_node_debug $NODE2_OPT &> /dev/null &
run dw_node_debug $NODE3_OPT &> /dev/null &
sleep 2

# nested: client -> node1 -> node2 -> node3
run dw_client_debug $CLIENT_OPT -n 10 -F dpdk://${DPDK_MAC[2]} -F dpdk://${DPDK_MAC[3]} -C 100 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 10" $TMP_CLIENT

# multi-forward: client -> node1 -> node2 AND node3
run dw_client_debug $CLIENT_OPT -n 10 -F dpdk://${DPDK_MAC[2]},dpdk://${DPDK_MAC[3]} -C 100 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 10" $TMP_CLIENT

# nack=1 (wait for fastest only)
run dw_client_debug $CLIENT_OPT -n 10 -F dpdk://${DPDK_MAC[2]},dpdk://${DPDK_MAC[3]},nack=1 -C 100 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 10" $TMP_CLIENT

# branched multi-forward
run dw_client_debug $CLIENT_OPT -n 10 -F dpdk://${DPDK_MAC[2]},branch -C 100 -F dpdk://${DPDK_MAC[3]},branch -C 200 -R -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 10" $TMP_CLIENT

kill_all SIGINT
sleep 1

rm -f $TMP_STORE $TMP_CLIENT
kill_all

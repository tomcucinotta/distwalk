#!/bin/bash
# Stress test: high packet counts, high send rates, multiple DPDK clients

. common.sh
. dpdk_common.sh

dpdk_check_root
dpdk_check_binary
dpdk_auto_setup 3
trap dpdk_auto_teardown EXIT

NODE_OPT="-b dpdk://${DPDK_IFACE[0]} -c 0"
CLIENT1_OPT="-b dpdk://${DPDK_IFACE[1]} --to dpdk://${DPDK_MAC[0]} --dpdk-rx-cpu 1 --dpdk-tx-cpu 2"
CLIENT2_OPT="-b dpdk://${DPDK_IFACE[2]} --to dpdk://${DPDK_MAC[0]} --dpdk-rx-cpu 3 --dpdk-tx-cpu 4"

TMP_CLIENT=$(mktemp /tmp/dw-dpdk-client-XXX.txt)

echo "--- high send rate ---"

run dw_node_debug $NODE_OPT &> /dev/null &
sleep 2

run dw_client_debug $CLIENT1_OPT -n 500 -C 0 -p 2 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 500" $TMP_CLIENT

kill_all SIGINT
sleep 1

echo "--- large packet sizes ---"

run dw_node_debug $NODE_OPT &> /dev/null &
sleep 2

run dw_client_debug $CLIENT1_OPT -n 100 -C 0 --ps=1400 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 100" $TMP_CLIENT

run dw_client_debug $CLIENT1_OPT -n 100 -C 0 --rs=1400 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 100" $TMP_CLIENT

kill_all SIGINT
sleep 1

echo "--- two clients simultaneously ---"

run dw_node_debug $NODE_OPT &> /dev/null &
sleep 2

TMP_C1=$(mktemp /tmp/dw-dpdk-client1-XXX.txt)
TMP_C2=$(mktemp /tmp/dw-dpdk-client2-XXX.txt)
run dw_client_debug $CLIENT1_OPT -n 500 -C 0 -p 10 > $TMP_C1 &
pid1=$!
run dw_client_debug $CLIENT2_OPT -n 500 -C 0 -p 10 > $TMP_C2 &
pid2=$!
wait $pid1 $pid2

cat $TMP_C1
grep -q "success: 500" $TMP_C1

cat $TMP_C2
grep -q "success: 500" $TMP_C2

kill_all SIGINT
sleep 1

rm -f $TMP_CLIENT $TMP_C1 $TMP_C2
kill_all

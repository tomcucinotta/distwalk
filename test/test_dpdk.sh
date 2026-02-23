#!/bin/bash

. common.sh
. dpdk_common.sh

dpdk_check_root
dpdk_check_binary
dpdk_auto_setup 2
trap dpdk_auto_teardown EXIT

NODE_OPT="-b dpdk://${DPDK_IFACE[0]} -c 0"
CLIENT_OPT="-b dpdk://${DPDK_IFACE[1]} --to dpdk://${DPDK_MAC[0]} --dpdk-rx-cpu 1 --dpdk-tx-cpu 2"

TMP_CLIENT=$(mktemp /tmp/dw-dpdk-client-XXX.txt)

run dw_node_debug $NODE_OPT &> /dev/null &
sleep 2

echo "--- basic compute ---"
run dw_client_debug $CLIENT_OPT -n 100 -C 0 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 100" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 100 -C 10 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 100" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 100 -C 100 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 100" $TMP_CLIENT

echo "--- compute with payload ---"
run dw_client_debug $CLIENT_OPT -n 50 -C 100 -p 25 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 50 -C 100 -p 50 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 100 -C 100 -p 100 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 100" $TMP_CLIENT

echo "--- random distributions ---"
run dw_client_debug $CLIENT_OPT -n 50 -C unif:min=50,max=200 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 50 -C exp:100 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 50 -C norm:100,std=20 -p 1000 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

echo "--- mixed distributions ---"
run dw_client_debug $CLIENT_OPT -n 50 -C unif:min=15,max=20 -p 18 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

run dw_client_debug $CLIENT_OPT -n 50 -C exp:100 -p unif:min=10,max=15 > $TMP_CLIENT
cat $TMP_CLIENT
grep -q "success: 50" $TMP_CLIENT

rm -f $TMP_CLIENT
kill_all

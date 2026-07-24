#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

tmp_node=$(mktemp /tmp/dw-test_proxy_threads-node-XXX.txt)
tmp_client=$(mktemp /tmp/dw-test_proxy_threads-client-XXX.txt)

node_bg -b :7892 &> $tmp_node
proxy_bg -b :7891 --to :7892
client --to :7891 -C 0 -n 1 &> $tmp_client

children=$(ls /proc/$(pidof dw_proxy_debug)/task)
echo "dw_proxy_debug children:"
echo "$children"
[ $(echo $children | grep -c "") -eq 1 ]

kill_all SIGKILL

rm $tmp_node
rm $tmp_client

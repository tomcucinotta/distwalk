#!/bin/bash

. common.sh

tmp=$(mktemp /tmp/test_retry_success-XXX.txt)

client_bg --to=tcp://127.0.0.1:7894 --retry-num 10 --retry-period 1000 &> $tmp

sleep 2
node_bg -b :7894

attempt=1
while ! grep -q "CONN allocated" $tmp; do
    echo "re-check $attempt"
    sleep 1

    if [[ $attempt -eq 5 ]]; then
        exit -1
    fi
    ((attempt++))
done

rm $tmp

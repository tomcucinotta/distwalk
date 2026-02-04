#!/usr/bin/env bash

CLIENT="./src/dw_client"
OUTPUT="adistwalk_results_12_load.csv"

K=20   # number of repetitions per test

# Test sizes (16KB → 16MB)
SIZES=(16KB 32KB 64KB 128KB 256KB 512KB 1MB 2MB)

SENDFILESIZES=(16KB 32KB 64KB 128KB 256KB 512KB 1MB 2MB 4MB 8MB 16MB)

echo "id,t,elapsed,file_size,useSendfile" > "$OUTPUT"

id=0

run_test() {
    local size=$1
    local mode=$2

    if [ "$mode" == "sendfile" ]; then
        cmd="$CLIENT -R sendfile,$size"
        flag=1
    else
        cmd="$CLIENT -L $size -R $size"
        flag=0
    fi

    for ((i=0;i<K;i++)); do

        result=$($cmd 2>/dev/null)

        # isolate the measurement line
        line=$(echo "$result" | grep "t:")

        t=$(echo "$line" | sed -n 's/.*t: \([0-9]*\) us.*/\1/p')
        elapsed=$(echo "$line" | sed -n 's/.*elapsed: \([0-9]*\) us.*/\1/p')

        if [[ -n "$t" && -n "$elapsed" ]]; then
            echo "$id,$t,$elapsed,$size,$flag" >> "$OUTPUT"
            ((id++))
        else
            echo "WARNING: parse failed for $size $mode"
        fi

        sleep 0.05
    done
}


for size in "${SIZES[@]}"; do
    echo "Testing NORMAL mode size=$size"
    run_test "$size" "normal"
done

for size in "${SENDFILESIZES[@]}"; do
    echo "Testing SENDFILE mode size=$size"
    run_test "$size" "sendfile"
done

echo "Benchmark complete -> $OUTPUT"
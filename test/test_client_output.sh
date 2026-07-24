#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

# creates a temporary directory for the test in tmp and ensures it is cleaned up on exit
TMPDIR=$(mktemp -d /tmp/dw-test_client_output-XXX)
trap 'rm -rf "$TMPDIR"; kill_all SIGINT' SIGINT SIGTERM EXIT ERR

#verifies that the output file contains a line matching the given regex
check_contains() {
    grep -Eq "$1" "$2"
}

#tests cases where it is expected that the client fails and that the error message contains the given string
check_fail_contains() {
    expected="$1"
    shift

    err="$TMPDIR/err.txt"

    set +e
    run dw_client_debug "$@" > /dev/null 2> "$err"
    status=$?
    id=$[$id+1]
    set -e

    [ $status -ne 0 ]
    grep -q "$expected" "$err"
}

node_bg

OUT="$TMPDIR/out.csv"
client -n 1 --output "$OUT"
check_contains "^[0-9]+,[0-9]+,0,0,0$" "$OUT"

OUT="$TMPDIR/out-sep.csv"
client -n 1 --output "$OUT,sep=;"
check_contains "^[0-9]+;[0-9]+;0;0;0$" "$OUT"

OUT="$TMPDIR/out-header.csv"
client -n 1 --output "$OUT,header=true"
check_contains "^t\(us\),elapsed\(us\),req_id,thr_id,sess_id$" "$OUT"
check_contains "^[0-9]+,[0-9]+,0,0,0$" "$OUT"

OUT="$TMPDIR/out-header-one.csv"
client -n 1 --output "$OUT,header=1"
check_contains "^t\(us\),elapsed\(us\),req_id,thr_id,sess_id$" "$OUT"
check_contains "^[0-9]+,[0-9]+,0,0,0$" "$OUT"

OUT="$TMPDIR/out-no-header-false.csv"
client -n 1 --output "$OUT,header=false"
check_contains "^[0-9]+,[0-9]+,0,0,0$" "$OUT"

OUT="$TMPDIR/out-no-header-zero.csv"
client -n 1 --output "$OUT,header=0"
check_contains "^[0-9]+,[0-9]+,0,0,0$" "$OUT"

OUT="$TMPDIR/out-sep-header.csv"
client -n 1 --output "$OUT,sep=#,header=true"
check_contains "^t\(us\)#elapsed\(us\)#req_id#thr_id#sess_id$" "$OUT"
check_contains "^[0-9]+#[0-9]+#0#0#0$" "$OUT"

OUT="$TMPDIR/out-nano.csv"
client -n 1 --nano --output "$OUT,sep=;,header=true"
check_contains "^t\(ns\);elapsed\(ns\);req_id;thr_id;sess_id$" "$OUT"
check_contains "^[0-9]+;[0-9]+;0;0;0$" "$OUT"

OUT="$TMPDIR/out-quoted-sep.csv"
client -n 1 --output "$OUT,sep=';',header=false"
check_contains "^[0-9]+;[0-9]+;0;0;0$" "$OUT"

OUT="$TMPDIR/out-n2.csv"
client -n 2 --output "$OUT"
check_contains "^[0-9]+,[0-9]+,0,0,0$" "$OUT"
check_contains "^[0-9]+,[0-9]+,1,0,0$" "$OUT"

OUT="$TMPDIR/out.txt"
client -n 1 --output "$OUT,sep=|"
check_contains "^t:[0-9]+\|elapsed:[0-9]+\|req_id:0\|thr_id:0\|sess_id:0$" "$OUT"

# tests that is there is not --output option then it shows output in the terminal
OUT="$TMPDIR/stdout.txt"
client -n 1 > "$OUT"
check_contains "t: [0-9]+ us, elapsed: [0-9]+ us, req_id: 0, thr_id: 0, sess_id: 0" "$OUT"

# Unknown output extensions must be rejected.
check_fail_contains "Unknown output file extension" --output "$TMPDIR/out.data,sep=|"

check_fail_contains "header= option" --output "$TMPDIR/bad-header.txt,header=true"
check_fail_contains "Wrong value for header=" --output "$TMPDIR/bad-header.csv,header=maybe"
check_fail_contains "Missing separator char" --output "$TMPDIR/bad-sep.csv,sep="
check_fail_contains "txt format" --output "$TMPDIR/bad-sep.txt,sep=_"
check_fail_contains "txt format" --output "$TMPDIR/bad-colon.txt,sep=:"
check_fail_contains "csv format" --output "$TMPDIR/bad-sep.csv,sep=_"
check_fail_contains "Missing file name" --output ",sep=;"

rm -rf "$TMPDIR"
kill_all SIGINT
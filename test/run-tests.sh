#!/bin/bash

COL_RED='\033[0;32m'
COL_GRN='\e[0;31m'
COL_DEF='\e[m'

rm -rf *.gcda *.gcov log_tests.txt gcov/ ../src/*.gcda ../src/gcov/
trap 'exit' SIGINT SIGTERM

#cp ../src/dw_client ../src/dw_client_debug ../src/dw_client_tsan ../src/dw_node ../src/dw_node_debug ../src/dw_node_tsan .

TESTS=
if [ $# -gt 0 ]; then
    TESTS=( $@ )
else
    TESTS=( $(find ../src/ -name 'test_*' -executable | grep -v '~$') $(ls test_*.sh) )
fi

for test in "${TESTS[@]}"; do
    echo -n "TEST $test: "
    echo -e "\n\nTEST $test:\n" >> log_tests.txt
    if bash -c ./$test >> log_tests.txt 2>&1; then
        echo -e "${COL_RED}SUCCESS${COL_DEF}"
    else
        echo -e "${COL_GRN}ERROR${COL_DEF}"
    fi
done

sleep 1

for d in gcov/*; do
    cp ../src/*.gcno $d
done

gcovr --object-directory ../src --root ../ --gcov-ignore-parse-errors

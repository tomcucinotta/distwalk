#!/bin/bash

COL_RED='\033[0;32m'
COL_GRN='\e[0;31m'
COL_YLW='\e[0;33m'
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

echo "List of all available tests (before filtering):"
printf '  - %s\n' "${TESTS[@]}"

EXCLUDE_PATTERNS=(
    #"*proxy*"
    #"test_client_ramp.*"
    #"test_skip.*"
    #"test_forward.sh"
    #"test_forward_self*"
    #"test_forward_skip*"
    #"test_forward_timeout*"
    #"test_multi_forward*"
    #"test_ssl*"
    #"test_accept_mode.*"
    #"test_accept_mode_parent.*"
    #"test_conn_drop*"
    #"test_poll_mode*"
    #"test_retry*"
    #"test_simple*"
    #"test_client_opts*"
    #"test_client_out*"
    #"test_compute*"
    #"test_connect*"
    #"test_distrib*"
    #"test_loadstor*"
    #"test_node*"
    #"test_sched*"
    #"test_script*"
    #"test_stats*"
)

is_excluded() {
    local name="$1"
    for pat in "${EXCLUDE_PATTERNS[@]}"; do
        case "$name" in
            $pat) return 0 ;;   # 0 = true --> excluded
        esac
    done
    return 1
}

if [[ ${#EXCLUDE_PATTERNS[@]} -gt 0 ]]; then
    filtered=()
    for t in "${TESTS[@]}"; do
        if is_excluded "$t"; then
            echo "  [EXCLUDED] $t" >&2
        else
            filtered+=("$t")
        fi
    done
    TESTS=("${filtered[@]}")
fi


run_test() {
    local test=$1
    local label=$2
    echo -n "TEST $label: "
    echo -e "\n\nTEST $label:\n" >> log_tests.txt
    bash -c ./$test >> log_tests.txt 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        echo -e "${COL_RED}SUCCESS${COL_DEF}"
    elif [ $rc -eq 77 ]; then
        echo -e "${COL_YLW}SKIPPED${COL_DEF} (non-root or missing USE_DPDK)"
    else
        echo -e "${COL_GRN}ERROR${COL_DEF}"
    fi
}


# test_poll_mode.sh already tests all poll modes, no need to iterate over them.
RUN_ONCE='test_poll_mode\.sh$'
SKIP_EPOLL_RE='test_poll_mode\.sh$'
SKIP_POLL_RE='test_poll_mode\.sh$'
SKIP_SELECT_RE='test_poll_mode\.sh$'

for test in "${TESTS[@]}"; do
    if [[ "$test" == *dpdk* ]]; then
        for mode in veth vf; do
            DPDK_MODE=$mode run_test "$test" "$test (dpdk=$mode)"
        done
        continue
    fi

    if [[ "$test" =~ $RUN_ONCE ]]; then
        run_test "$test" "$test (covers all modes)"
        continue
    fi

    if ! [[ "$test" =~ $SKIP_EPOLL_RE ]]; then
        POLL_MODE=epoll run_test "$test" "$test (poll-mode=epoll)"
    fi

    if ! [[ "$test" =~ $SKIP_POLL_RE ]]; then
        POLL_MODE=poll run_test "$test" "$test (poll-mode=poll)"
    fi

    if ! [[ "$test" =~ $SKIP_SELECT_RE ]]; then
        POLL_MODE=select run_test "$test" "$test (poll-mode=select)"
    fi
done

sleep 1

for d in gcov/*; do
    cp ../src/*.gcno $d
done

# Set ownership on gcov folder and all subdirectories and files inside it
if [ -n "$SUDO_USER" ]; then
    [ -d gcov ] && chown -R "$SUDO_UID:$SUDO_GID" gcov
fi

if command -v gcovr &> /dev/null; then
    gcovr --object-directory ../src --root ../ --gcov-ignore-parse-errors
else
    echo "gcovr is not installed"
fi

kill_all() {
    sig=SIGINT
    if [ "$1" != "" ]; then
        sig="$1"
    fi
    for p in dw_client dw_node dw_client_debug dw_node_debug dw_proxy dw_proxy_debug; do
        kill -$sig $(pidof $p) &> /dev/null || true
    done
    wait

    id=0
}

trap 'kill_all SIGINT' SIGINT SIGTERM EXIT ERR
set -e
shopt -s expand_aliases

export GCOV_PREFIX_STRIP=$(pwd | sed -e 's#/##' | tr "/" "\n" | wc -l)

id=0

check_executable() {
    command -v ../src/$1 >/dev/null 2>&1 || { echo >&2 "Executable '$1' missing --  Aborting."; return -1; }
}

run() {
    outdir=gcov/prog-$id
    mkdir -p $outdir
    curdir=$(pwd)
    (cd ../src; PATH="$PATH:." GCOV_PREFIX=$curdir/$outdir "$@")
}

client() {
    check_executable dw_client_debug || { exit -1; }
    run dw_client_debug "$@"
    id=$[$id+1]
}

client_bg() {
    check_executable dw_client_debug || { exit -1; }
    run dw_client_debug "$@" &
    id=$[$id+1]
}

strace_client() {
    check_executable dw_client_debug || { exit -1; }
    run strace -f dw_client_debug "$@"
    id=$[$id+1]
}

# DW_NODE_ARGS contains passed args + merged POLL_MODE if it exists and was not there already
inject_poll_mode() {
    DW_NODE_ARGS=( "$@" )
    if [ -z "$POLL_MODE" ]; then
        return 0
    fi
    for a in "$@"; do
        case "$a" in
            --poll-mode|--poll-mode=*|-p)
                return 0;;
        esac
    done
    DW_NODE_ARGS+=( --poll-mode "$POLL_MODE" )
}

node() {
    check_executable dw_node_debug || { exit -1; }
    inject_poll_mode "$@"
    run dw_node_debug "${DW_NODE_ARGS[@]}"
    id=$[$id+1]
}

node_bg() {
    check_executable dw_node_debug || { exit -1; }
    inc=1
    if [ "$1" == "--wait-bind-num" ]; then
        inc=$2
        shift 2
    fi
    inject_poll_mode "$@"
    n_beg=$(netstat -anp --inet 2> /dev/null | grep -c dw_node || true)
    n_exp=$[$n_beg+$inc]
    run dw_node_debug "${DW_NODE_ARGS[@]}" &
    id=$[$id+1]
    for ((i=0; i<5; i++)); do
        n=$(netstat -anp --inet 2> /dev/null | grep -c dw_node || true)
        if [ $n -eq $n_exp ]; then
            break;
        fi
        echo "dw_node_debug showing up $n times, not $n_exp ones up on netstat, waiting..."
        sleep 0.2
    done
}

strace_node_bg() {
    check_executable dw_node_debug || { exit -1; }
    inc=1
    if [ "$1" == "--wait-bind-num" ]; then
        inc=$2
        shift 2
    fi
    inject_poll_mode "$@"
    n_beg=$(netstat -anp --inet 2> /dev/null | grep -c dw_node || true)
    n_exp=$[ $n_beg + $inc ]
    run strace -f dw_node_debug "${DW_NODE_ARGS[@]}" &
    id=$[$id+1]
    for ((i=0; i<5; i++)); do
        n=$(netstat -anp --inet 2> /dev/null | grep -c dw_node || true)
        if [ $n -eq $n_exp ]; then
            break;
        fi
        echo "dw_node_debug showing up $n times, not $n_exp ones up on netstat on netstat, waiting..."
        sleep 0.2
    done
}

proxy() {
    check_executable dw_proxy_debug || { exit -1; }
    run dw_proxy_debug "$@"
    id=$[$id+1]
}

proxy_bg() {
    check_executable dw_proxy_debug || { exit -1; }
    run dw_proxy_debug "$@" &
    id=$[$id+1]
}

kill_all SIGKILL

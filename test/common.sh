kill_all() {
    sig=SIGINT
    if [ "$1" != "" ]; then
        sig="$1"
    fi
    for p in dw_client dw_node dw_client_debug dw_node_debug; do
        if $(pidof $p > /dev/null 2>&1); then
            kill -$sig $(pidof $p)
        fi
    done
    wait

    id=0
}

trap 'kill_all SIGINT' SIGINT SIGTERM EXIT ERR
set -e
shopt -s expand_aliases

export GCOV_PREFIX_STRIP=$(pwd | sed -e 's#/##' | tr "/" "\n" | wc -l)

id=0

run() {
    outdir=gcov/prog-$id
    mkdir -p $outdir
    curdir=$(pwd)
    (cd ../src; PATH="$PATH:." GCOV_PREFIX=$curdir/$outdir "$@")
}

client() {
    run dw_client_debug "$@"
    id=$[$id+1]
}

client_bg() {
    run dw_client_debug "$@" &
    id=$[$id+1]
}

strace_client() {
    run strace -f dw_client_debug "$@"
    id=$[$id+1]
}

node() {
    run dw_node_debug "$@"
    id=$[$id+1]
}

node_bg() {
    inc=1
    if [ "$1" == "--wait-bind-num" ]; then
        inc=$2
        shift 2
    fi
    n_beg=$(netstat -anp --inet 2> /dev/null | grep -c dw_node || true)
    n_exp=$[$n_beg+$inc]
    run dw_node_debug "$@" &
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
    inc=1
    if [ "$1" == "--wait-bind-num" ]; then
        inc=$2
        shift 2
    fi
    n_beg=$(netstat -anp --inet 2> /dev/null | grep -c dw_node || true)
    n_exp=$[ $n_beg + $inc ]
    run strace -f dw_node_debug "$@" &
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

kill_all SIGKILL

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
}

trap 'kill_all SIGINT; wait' SIGINT SIGTERM EXIT ERR
set -e
shopt -s expand_aliases

export GCOV_PREFIX_STRIP=$(pwd | sed -e 's#/##' | tr "/" "\n" | wc -l)

client() {
    id=$(ps aux | grep dw_client_debug | grep -v grep | wc -l)
    mkdir -p gcov/client$id
    GCOV_PREFIX=gcov/client$id ./dw_client_debug "$@"
}

strace_client() {
    sleep 0.5
    GCOV_PREFIX=gcov/client strace -f ./dw_client_debug "$@"
}

node() {
    id=$(ps aux | grep dw_node_debug | grep -v grep | wc -l)
    mkdir -p gcov/node$id
    GCOV_PREFIX=gcov/node$id ./dw_node_debug "$@"
}

node_bg() {
    id=$(ps aux | grep dw_node_debug | grep -v grep | wc -l)
    mkdir -p gcov/node$id
    GCOV_PREFIX=gcov/node$id ./dw_node_debug "$@" &
    for ((i=0; i<5; i++)); do
        if [ $(netstat -anp --inet | grep dw_node_debug | wc -l) -eq $[ $id + 1 ] ]; then
            break;
        fi
        echo "dw_node_debug not showing up on netstat yet, waiting..."
        sleep 0.2
    done
}

strace_node() {
    id=$(ps aux | grep dw_node_debug | grep -v grep | wc -l)
    mkdir -p gcov/node$id
    GCOV_PREFIX=gcov/node$id strace -f ./dw_node_debug "$@"
    for ((i=0; i<5; i++)); do
        if [ $(netstat -anp --inet | grep dw_node_debug | wc -l) -eq $[ $id + 1 ] ]; then
            break;
        fi
        echo "dw_node_debug not showing up on netstat yet, waiting..."
        sleep 0.2
    done
}

kill_all SIGKILL

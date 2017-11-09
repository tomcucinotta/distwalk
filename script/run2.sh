#!/bin/bash

BLACK='\033[0;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'

echo() {
    /bin/echo -e ${BLACK}$(date +%H.%M.%S): "$@"${BLACK}
}

echo "${GREEN}Starting on $(date) @ $(hostname) - $(uname -r)"

. vars.sh

NODE_CPUL=$(/bin/echo $NODE_CPUS | sed -e 's/ /,/g')
CLIENT_CPUL=$(/bin/echo $CLIENT_CPUS | sed -e 's/ /,/g')

# Relative to home directory or absolute (to be used in ssh commands)
DIR=${DIR-cloudwalk}

run_on() {
    host=$1
    shift
    cmd="cd $DIR; . vars.sh; $@"
    echo "Running $cmd on $host..."
    ssh $host "$cmd"
}

echo "Dumping env:"
env
echo ""

echo "Synchronizing software with client machine $CLIENT..."
run_on $CLIENT mkdir -p $DIR
rsync -avz -e ssh *.sh ../src/node ../src/node_debug ../src/client ../src/client_debug $CLIENT:$DIR

echo "Synchronizing software with server machine $SERVER..."
run_on $SERVER mkdir -p $DIR
rsync -avz -e ssh *.sh ../src/node ../src/node_debug ../src/client ../src/client_debug $SERVER:$DIR

echo "Killing existing instances on server $SERVER if any..."
run_on $SERVER killall client node client_debug node_debug 2> /dev/null

echo "Killing existing instances on client $CLIENT if any..."
run_on $CLIENT killall client node client_debug node_debug 2> /dev/null

echo "Node setup:"
run_on $SERVER sudo ./setup.sh

echo "Client setup:"
run_on $CLIENT sudo ./setup.sh

echo "Node NIC configuration and limits:"
run_on $SERVER sudo ./tc.sh show

echo "Node routing table:"
run_on $SERVER /sbin/route -n

echo "Client NIC configuration and limits:"
run_on $CLIENT sudo ./tc.sh show

echo "Client routing table:"
run_on $CLIENT /sbin/route -n

# sleep-time between exps rounds
PAUSE=0

if ! run_on $SERVER ./check.sh $NODE_CPUS; then
    echo "${RED}check.sh failed on $SERVER"
    exit -1
fi

CLIENT_IFACE=$(ssh $CLIENT /sbin/ip link show | grep -v LOOPBACK | grep 'state UP.*DEFAULT' | sed -e 's/[0-9]\+: \([a-z0-9]\+\): .*/\1/')
SERVER_IFACE=$(ssh $SERVER /sbin/ip link show | grep -v LOOPBACK | grep 'state UP.*DEFAULT' | sed -e 's/[0-9]\+: \([a-z0-9]\+\): .*/\1/')

if [ "$SPEED" != "" ]; then
    echo "Setting speed of $SERVER_IFACE to $SPEED on $SERVER"
    ssh $SERVER sudo /sbin/ethtool -s $SERVER_IFACE speed $SPEED duplex full
    echo "Setting speed of $CLIENT_IFACE to $SPEED on $CLIENT"
    ssh $CLIENT sudo /sbin/ethtool -s $CLIENT_IFACE speed $SPEED duplex full
fi

while ! ping -c 1 $CLIENT || ! ping -c 1 $SERVER; do
    echo "Waiting to be able to reach $CLIENT and $SERVER again"
    sleep 1
done

CLIENT_NBW=$(ssh $CLIENT sudo /sbin/ethtool $CLIENT_IFACE | grep Speed: | sed -e 's#.*Speed: \(.*\)/s#\1#' | tr "A-Z" "a-z")
echo "CLIENT_IFACE=$CLIENT_IFACE CLIENT_NBW=$CLIENT_NBW"
SERVER_NBW=$(ssh $SERVER sudo /sbin/ethtool $SERVER_IFACE | grep Speed: | sed -e 's#.*Speed: \(.*\)/s#\1#' | tr "A-Z" "a-z")
echo "SERVER_IFACE=$SERVER_IFACE SERVER_NBW=$SERVER_NBW"

if [ "$CLIENT_NBW" != "$SERVER_NBW" ]; then
    echo "${RED}Error: client/server network bandwidth settings are not the same!"
    exit -1
fi

NBW=$SERVER_NBW

echo ""
echo "${GREEN}Looping over configurations..."
echo ""

outdir=bw$NBW-bdir-p$PKTS
mkdir -p $outdir

for PS in $PSS; do
    for DT in $DTS; do
	for BW in $BWS; do
	    # Round bc output
	    CT=$(/bin/echo "$DT * $BW" | bc -l | sed -e 's/\..*//')

	    echo ""
	    echo "Trying with PS=$PS, BW=$BW, DT=$DT, CT=$CT"
	    echo ""

	    logfname=log-t$DT-s$PS-c$CT.txt

	    if [ -f $outdir/$logfname ]; then
		echo "Skipping because of already existing file: $outdir/log-t$DT-s$PS-c$CT.txt"
		continue;
	    fi

	    echo "Starting server on $SERVER"
	    run_on $SERVER taskset -c $NODE_CPUL ./node &

	    echo "Launching client on $CLIENT"
	    run_on $CLIENT "echo logged && taskset -c $CLIENT_CPUL ./client -s $SERVER -c $PKTS -p $DT -ea -ps $PS -C $CT -ec > $logfname"

	    echo "Client done, copying $logfname..."
	    scp $CLIENT:$DIR/$logfname $outdir/$logfname

	    echo "Killing node on $SERVER..."
	    run_on $SERVER killall node node_debug

	    echo "Waiting for node to die"
	    wait
	done
	echo "Sleeping for $PAUSE secs..."
	sleep $PAUSE
    done
done

echo "Client teardown:"
run_on $CLIENT sudo ./teardown.sh

echo "Node teardown:"
run_on $SERVER sudo ./teardown.sh

echo "Done, quitting."

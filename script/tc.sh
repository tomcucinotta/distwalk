#!/bin/bash
#
#  tc uses the following units when passed as a parameter.
#  kbps: Kilobytes per second
#  mbps: Megabytes per second
#  kbit: Kilobits per second
#  mbit: Megabits per second
#  bps: Bytes per second
#       Amounts of data can be specified in:
#       kb or k: Kilobytes
#       mb or m: Megabytes
#       mbit: Megabits
#       kbit: Kilobits
#  To get the byte figure from bits, divide the number by 8 bit
#

#
# Name of the traffic control command.
TC="sudo /sbin/tc"

# The network interface we're planning on limiting bandwidth.
#IFACE=eth0             # Interface
IFACE=${IFACE:-$(route -n | grep '^0.0.0.0' | sed -e 's/.* \([a-z0-9]\+\)$/\1/')}

# Download limit (in mega bits)
DNLD=${DNLD:-1mbit}          # DOWNLOAD Limit

# Upload limit (in mega bits)
UPLD=${UPLD:-1mbit}          # UPLOAD Limit

# IP address of the machine we are controlling
#IP=216.3.128.12     # Host IP
IP=${IP:-$(/sbin/ifconfig $IFACE | grep inet | sed -e 's/[[:blank:]]*inet //' -e 's/addr://' | cut -d ' ' -f1)}

echo IFACE=$IFACE, IP=$IP, IP2=$IP2, DNLD=$DNLD, UPLD=$UPLD

if [ "$1" = "start" -a "$IP2" = "" ]; then
    echo "Error: you need to provide the target IP address!"
    echo "Usage: IP2=a.b.c.d $0 {start|stop|show}"
    exit -1
fi

# Filter options for limiting the intended interface.
U32="$TC filter add dev $IFACE protocol ip parent 1:0 prio 1 u32"

start() {

# We'll use Hierarchical Token Bucket (HTB) to shape bandwidth.
# For detailed configuration options, please consult Linux man
# page.

    $TC qdisc add dev $IFACE root handle 1: htb default 30
    $TC class add dev $IFACE parent 1: classid 1:1 htb rate $DNLD
    $TC class add dev $IFACE parent 1: classid 1:2 htb rate $UPLD
    $U32 match ip dst $IP/32 match ip src $IP2/32 flowid 1:1
    $U32 match ip src $IP/32 match ip dst $IP2/32 flowid 1:2

# The first line creates the root qdisc, and the next two lines
# create two child qdisc that are to be used to shape download
# and upload bandwidth.
#
# The 4th and 5th line creates the filter to match the interface.
# The 'dst' IP address is used to limit download speed, and the
# 'src' IP address is used to limit upload speed.

}

stop() {

# Stop the bandwidth shaping.
    $TC qdisc del dev $IFACE root

}

restart() {

# Self-explanatory.
    stop
    sleep 1
    start

}

show() {

    /sbin/ifconfig $IFACE
    /sbin/ethtool $IFACE
    /sbin/route -n

    # Display status of traffic control status.
    $TC -s qdisc ls dev $IFACE
    $TC class show dev $IFACE
    $TC filter show dev $IFACE
}

case "$1" in

  start)

    echo -n "Starting bandwidth shaping: "
    start
    echo "done"
    ;;

  stop)

    echo -n "Stopping bandwidth shaping: "
    stop
    echo "done"
    ;;

  restart)

    echo -n "Restarting bandwidth shaping: "
    restart
    echo "done"
    ;;

  show)

    echo "Bandwidth shaping status for $IFACE:"
    show
    echo ""
    ;;

  *)

    pwd=$(pwd)
    echo "Usage: tc.bash {start|stop|restart|show}"
    ;;

esac

exit 0

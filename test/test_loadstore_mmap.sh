#!/bin/bash

mydir=$(dirname "$0")
source "$mydir/common.sh"

TMP=$(tmpfile dw-test_loadstore_mmap)
node_log=$(tmpfile dw-test_loadstore_mmap-log)

SIZE=64000000

# mmap storage: the file is sized to the whole storage size at startup
node_bg -s ${TMP},mmap,size=$SIZE
[ $(stat -c %s $TMP) -eq $SIZE ]

client -S 32000000
client -S 32000000 # fills the storage exactly
client -S 1024     # rewinds to offset 0
client -L 1024
client -L 33554432
client --load-offset unif:min=0:max=3071 -L 1024
client -L size=[1024],offset=[unif:min=0:max=3071]
client -S size=[1024],offset=[unif:min=0:max=3071]

# out-of-range accesses are truncated/skipped, without crashing the node
client -S size=[1024],offset=[63999000]
client -L size=[4096],offset=[63999000]
client -S size=[1024],offset=[70000000]
client -L size=[1024],offset=[70000000]
client -L 1024
[ $(stat -c %s $TMP) -eq $SIZE ]

kill_all SIGINT

# msync() calls are checked through the MSYNC lines in the debug log of the node

# default: msync(MS_ASYNC) after each STORE
node_bg -s ${TMP},mmap,size=$SIZE &> $node_log
client --store-offset 0 -S sync,65536
client --store-offset 0 -S nosync,65536
kill_all SIGINT
[ $(grep -c "MSYNC: MS_ASYNC \[0, 65536)" $node_log) -eq 2 ]
(! grep -q "MSYNC: MS_SYNC" $node_log)

# sync: msync(MS_SYNC) after each sync STORE, MS_ASYNC after nosync ones
node_bg -s ${TMP},mmap,sync,size=$SIZE &> $node_log
client --store-offset 0 -S sync,65536
client --store-offset 0 -S nosync,65536
kill_all SIGINT
[ $(grep -c "MSYNC: MS_SYNC \[0, 65536)" $node_log) -eq 1 ]
[ $(grep -c "MSYNC: MS_ASYNC \[0, 65536)" $node_log) -eq 1 ]

# sync=period: no msync() after each STORE, but a periodic msync(MS_SYNC)
# of the range written in the meantime; sync STOREs are replied to only
# after the periodic msync()
node_bg -s ${TMP},mmap,sync=100ms,size=$SIZE &> $node_log
client --store-offset 4096 -S sync,8192 -n 5
kill_all SIGINT
[ $(grep -c "MSYNC: MS_SYNC \[4096, 12288)" $node_log) -ge 1 ]
(! grep -q "MSYNC: MS_ASYNC" $node_log)

# sync STOREs still complete with periodic msync()
node_bg -s ${TMP},mmap,sync=50ms,size=$SIZE
client -S sync,4096 -n 3
client -S sync,4096 -L 4096 -n 3
kill_all SIGINT

# mmap with count=: one mmap()ed file per device
node_bg -s ${TMP}_%d,mmap,size=1000000,count=2
[ $(stat -c %s ${TMP}_0) -eq 1000000 ]
[ $(stat -c %s ${TMP}_1) -eq 1000000 ]
client -S size=[1000],dev=0 -S size=[1000],dev=1 -L size=[1000],dev=1
kill_all SIGINT
rm -f ${TMP}_0 ${TMP}_1

# mmap and odirect are mutually exclusive
(! node -s ${TMP},mmap,odirect)

rm $node_log
rm $TMP

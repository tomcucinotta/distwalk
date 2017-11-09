#!/bin/bash

mydir=$(dirname $0)

echo "#NBW PS DT BW CT AVG P90 P99 P999 MAX" > stats.dat

for PS in 128 256 512 1024 2048; do
    for DT in 800 900 1000 1250 1500 1750 2000 2500 5000; do
        for BW in 0.5 0.6 0.7 0.8 0.9; do
	    # Round bc output
	    CT=$(/bin/echo "$DT * $BW" | bc -l | sed -e 's/\..*//')
	    for nbw in 10 100; do
		fname=bw${nbw}mb-bdir-p10000/log-t$DT-s$PS-c$CT.txt
		avg=$($mydir/log2dat.sh $fname | datastat | cut -d ' ' -f 2 | tail -n +2)
		max=$($mydir/log2dat.sh $fname | datastat --no-avg --max | cut -d ' ' -f 2 | tail -n +2)
		p90=$($mydir/log2dat.sh $fname | $mydir/dat2cdf.sh | $mydir/cdf-to-perc.sh -p 0.90)
		p99=$($mydir/log2dat.sh $fname | $mydir/dat2cdf.sh | $mydir/cdf-to-perc.sh -p 0.99)
		p999=$($mydir/log2dat.sh $fname | $mydir/dat2cdf.sh | $mydir/cdf-to-perc.sh -p 0.999)
		echo $nbw $PS $DT $BW $CT $avg $p90 $p99 $p999 $max >> stats.dat
	    done
	done
    done
done

#!/bin/bash

mydir=$(dirname $0)

export LC_ALL=C

NBWS=${NBWS:-$(ls -d bw*-bdir-p* | sed -e 's/bw\([0-9kmb]\+\)-.*/\1/' | sort -n | uniq)}
echo NBWS=$NBWS

NPKTS=${NPKTS:-$(ls -d bw*-bdir-p* | sed -e 's/bw.*-bdir-p\([0-9]\+\)/\1/' | sort -n | uniq)}
echo NPKTS=$NPKTS

for NPKT in $NPKTS; do
    echo "#NBW PS DT BW CT AVG P90 P99 P999 MAX" > stats-$NPKT.dat
    for nbw in $NBWS; do
	echo nbw=$nbw

	DTS=${DTS:-$(cd bw$nbw-bdir-p$NPKT && ls log*.txt | sed -e 's/.*-t\([0-9]\+\)-.*/\1/' | sort -n | uniq)}
	echo DTS=$DTS

	PSS=${PSS:-$(cd bw$nbw-bdir-p$NPKT && ls log*.txt | sed -e 's/.*-s\([0-9]\+\)-.*/\1/' | sort -n | uniq)}
	echo PSS=$PSS

	for PS in $PSS; do
	    echo PS=$PS
	    for DT in $DTS; do
		echo DT=$DT
		CTS=$(cd bw$nbw-bdir-p$NPKT && ls log-t$DT-*.txt | sed -e 's/.*-c\([0-9]\+\)[^0-9].*/\1/' | sort -n | uniq)
		echo CTS=$CTS
		for CT in $CTS; do
		    # Round bc output
		    BW=$(/bin/echo "$CT / $DT" | bc -l | sed -e 's/^\./0\./' -e 's/0\+$//')
		    echo BW=$BW
		    fname=bw${nbw}-bdir-p$NPKT/log-t$DT-s$PS-c$CT.txt
		    tmp=$(tempfile)
		    $mydir/log2dat.sh $fname > $tmp
		    avg=$(cat $tmp | cut -d ' ' -f 2 | datastat --no-header)
		    max=$(cat $tmp | cut -d ' ' -f 2 | datastat --no-header --no-avg --max)
		    p90=$(cat $tmp | $mydir/dat2cdf.sh | $mydir/cdf-to-perc.sh -p 0.90)
		    p99=$(cat $tmp | $mydir/dat2cdf.sh | $mydir/cdf-to-perc.sh -p 0.99)
		    p999=$(cat $tmp | $mydir/dat2cdf.sh | $mydir/cdf-to-perc.sh -p 0.999)
		    echo $nbw $PS $DT $BW $CT $avg $p90 $p99 $p999 $max >> stats-$NPKT.dat
		    rm $tmp
		done
	    done
	done
    done
done

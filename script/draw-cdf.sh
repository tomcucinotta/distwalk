#!/bin/bash

mydir=$(dirname $0)

. vars.sh

NBWS=${NBWS:-$(ls -d bw*-bdir-p* | sed -e 's/bw\([0-9kmb]\+\)-.*/\1/' | sort -n | uniq)}
echo NBWS=$NBWS

NPKTS=${NPKTS:-$(ls -d bw*-bdir-p* | sed -e 's/bw.*-bdir-p\([0-9]\+\)/\1/' | sort -n | uniq)}
echo NPKTS=$NPKTS

for NPKT in $NPKTS; do
    for PS in $PSS; do
	for DT in $DTS; do
	    for BW in $BWS; do
		# Round bc output
		CT=$(/bin/echo "$DT * $BW" | bc -l | sed -e 's/\..*//')

		cat > do.gp <<EOF
#!/usr/bin/gnuplot

set terminal pdf
set output 'cdf-p$NPKT-t$DT-s$PS-c$CT.pdf'

set grid
set xlabel 'Response-time (ms)'
set ylabel 'CDF'
plot \\
EOF
		for NBW in $NBWS; do
		    cat >> do.gp <<EOF
  '< $mydir/log2dat.sh bw$NBW-bdir-p$NPKT/log-t$DT-s$PS-c$CT.txt | $mydir/dat2cdf.sh' u (\$1/1000):2 t 'BW=$NBW DT=$DT PS=$PS CT=$CT' w l lw 3, \\
EOF
		done
		echo "0 t '' " >> do.gp
		gnuplot do.gp || exit -1
	    done
	done
    done
done

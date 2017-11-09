#!/bin/bash

mydir=$(dirname $0)

. vars.sh

NBWS=${NBWS:-$(ls -d bw*-bdir-p* | sed -e 's/bw\([0-9kmb]\+\)-.*/\1/' | sort -n | uniq)}
echo NBWS=$NBWS

NPKTS=${NPKTS:-$(ls -d bw*-bdir-p* | sed -e 's/bw.*-bdir-p\([0-9]\+\)/\1/' | sort -n | uniq)}
echo NPKTS=$NPKTS

for NPKT in $NPKTS; do
    for NW in $NBWS; do
	for PS in $PSS; do
	    cat > do.gp <<EOF
#!/usr/bin/gnuplot

set terminal pdf
set output 'stat-p$NPKT-dt-nw$NW-s$PS.pdf'

set grid
set xlabel 'Average period (ms)'
set ylabel 'Response time (ms)'
set title 'NBW=$NW PS=$PS'

set xtics 0.5 2
set key top left

set logscale x
set logscale y

plot [0.5:8] \\
  0 t '' \\
EOF
	    i=0
            for BW in $BWS; do
		cat >> do.gp <<EOF
  , "< grep '^$NW $PS [0-9]\\\\+ $BW ' stats-$NPKT.dat" u (\$3/1000*(1+0.0$i*3)):(\$6/1000):(\$6/1000):(\$8/1000) t 'AVG-|P99 BW=$BW' w errorbars lw 2 \\
EOF
		i=$[$i+1]
	    done
	    echo >> do.gp
	    gnuplot do.gp
	done
    done
done

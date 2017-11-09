#!/bin/bash

mydir=$(dirname $0)

. vars.sh

NBWS=${NBWS:-$(ls -d bw*-bdir-p* | sed -e 's/bw\([0-9kmb]\+\)-.*/\1/' | sort -n | uniq)}
echo NBWS=$NBWS

NPKTS=${NPKTS:-$(ls -d bw*-bdir-p* | sed -e 's/bw.*-bdir-p\([0-9]\+\)/\1/' | sort -n | uniq)}
echo NPKTS=$NPKTS

for NPKT in $NPKTS; do
    for NW in $NBWS; do
	for DT in $DTS; do
	    cat > do.gp <<EOF
#!/usr/bin/gnuplot

set terminal pdf
set output 'stat-p$NPKT-bw-nw$NW-t$DT.pdf'

set grid
set xlabel 'Computational bandwidth'
set ylabel 'Response time (ms)'
set title 'NW=$NW DT=$DT'
set key top left

set xtics 0.1

plot \\
  0 t '' \\
EOF
	    i=0
            for PS in $PSS; do
		cat >> do.gp <<EOF
  , "< grep '^$NW $PS $DT [0-9.]\\\\+ ' stats-$NPKT.dat" u (\$4+0.0$i):(\$6/1000):(\$6/1000):(\$8/1000) t 'AVG-|P99 PS=$PS' w errorbars lw 2 \\
EOF
		i=$[$i+1];
	    done
	    echo >> do.gp
	    gnuplot do.gp
	done
    done
done

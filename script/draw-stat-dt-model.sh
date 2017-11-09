#!/bin/bash

mydir=$(dirname $0)

. vars.sh
echo BWS=$BWS

NBWS=${NBWS:-$(ls -d bw*-bdir-p* | sed -e 's/bw\([0-9kmb]\+\)-.*/\1/' | sort -n | uniq)}
echo NBWS=$NBWS

NPKTS=${NPKTS:-$(ls -d bw*-bdir-p* | sed -e 's/bw.*-bdir-p\([0-9]\+\)/\1/' | sort -n | uniq)}
echo NPKTS=$NPKTS

for NPKT in $NPKTS; do
    for NW in $NBWS; do
	for PS in $PSS; do
            for BW in $BWS; do
		cat > do.gp <<EOF
#!/usr/bin/gnuplot

set terminal pdf
set output 'stat-p$NPKT-dt-model-nw$NW-s$PS-bw$BW.pdf'

set grid
set xlabel 'Average period (ms)'
set ylabel 'Response time (ms)'
set title 'NBW=$NW PS=$PS BW=$BW'

set xtics 0.5 2
set key top left

set logscale x
set logscale y

plot [0.5:8] \\
  "< grep '^$NW $PS [0-9]\\\\+ $BW ' stats-$NPKT.dat" u (\$3/1000):(\$6/1000):(\$6/1000):(\$8/1000) t 'AVG-|P99 (experimental)' w errorbars lw 2, \\
  "< grep '^$NW $PS [0-9]\\\\+ $BW ' stats-$NPKT.dat" u (\$3/1000*1.02):(0.252+1000/(1000000/(\$5+30.5)-1000000/\$3)):(0.252+1000/(1000000/(\$5+30.5)-1000000/\$3)):(0.252-1000*log(1-0.99)/(1000000/\$5-1000000/\$3)) t 'AVG-|P99 (theoretical)' w errorbars lw 2
EOF
		gnuplot do.gp
	    done
	done
    done
done

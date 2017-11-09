#!/bin/bash

mydir=$(dirname $0)

NBWS=${NBWS:-$(ls -d bw*-bdir-p* | sed -e 's/bw\([0-9kmb]\+\)-.*/\1/' | sort -n | uniq)}
echo NBWS=$NBWS

NPKTS=${NPKTS:-$(ls -d bw*-bdir-p* | sed -e 's/bw.*-bdir-p\([0-9]\+\)/\1/' | sort -n | uniq)}
echo NPKTS=$NPKTS

for NPKT in $NPKTS; do
    for nbw in $NBWS; do
	DTS=${DTS:-$(cd bw$nbw-bdir-p$NPKT && ls log*.txt | sed -e 's/.*-t\([0-9]\+\)-.*/\1/' | sort -n | uniq)}
	echo DTS=$DTS
	for DT in $DTS; do
	    echo DT=$DT
	    cat > do.gp <<EOF
#!/usr/bin/gnuplot

set terminal pdf
set output 'stat-nbw-nw$nbw-t$DT-p$NPKT.pdf'

set grid
set xlabel 'Sent bandwidth (kB/s)'
set ylabel 'Response time (ms)'
set title 'NBW=$nbw DT=$DT'

set logscale x
set logscale y
set xtics 128 2

set key top left

plot [:32768] [] \\
  0 t '' \\
EOF
	    i=0
            for BW in 0.5 0.6 0.7 0.8 0.9; do
		# Round bc output
		cat >> do.gp <<EOF
  , "< grep '^$nbw [0-9]\\\\+ $DT $BW ' stats-$NPKT.dat" u (\$2*1.$i):(\$6/1000):(\$6/1000):(\$8/1000) t 'AVG-|P99 BW=$BW' w errorbars lw 2 \\
EOF
		i=$[$i+1]
	    done
	    echo >> do.gp
	    gnuplot do.gp
	done
    done
done

#  , "< grep '^$nbw [0-9]\\\\+ $DT $BW ' stats-$NPKT.dat" u (\$2*1000000/\$3/1024*1.$i):(\$6/1000):(\$6/1000):(\$8/1000) t 'AVG-|P99 BW=$BW' w errorbars lw 2 \\

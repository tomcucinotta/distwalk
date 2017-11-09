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
set output 'stat-p$NPKT-ps-nw$NW-t$DT.pdf'

set grid
set xlabel 'Sent packet size (bytes)'
set ylabel 'Response time (ms)'
set title 'NW=$NW DT=$DT'

set logscale x
set xtics 128 2

plot [128:16384*1.4] \\
  0 t '' \\
EOF
	    i=0
            for BW in $BWS; do
		# Round bc output
		CT=$(/bin/echo "$DT * $BW" | bc -l | sed -e 's/\..*//')
		cat >> do.gp <<EOF
  , "< grep '^$NW [0-9]\\\\+ $DT $BW ' stats-$NPKT.dat" u (\$2*(1 + 0.$i*0.5)):(\$6/1000):(\$6/1000):(\$8/1000) t 'AVG-|P99 BW=$BW' w errorbars lw 2 \\
EOF
		i=$[$i+1]
	    done
	    echo >> do.gp
	    gnuplot do.gp
	done
    done
done

  # , "< grep '^$NW [0-9]\\\\+ $DT $BW ' stats-$NPKT.dat" u 2:(\$7/1000) t 'P90 NW=$NW DT=$DT BW=$BW' w lp \\
  # , "< grep '^$NW [0-9]\\\\+ $DT $BW ' stats-$NPKT.dat" u 2:(\$10/1000) t 'MAX NW=$NW DT=$DT BW=$BW' w lp \\

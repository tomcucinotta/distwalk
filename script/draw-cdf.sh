#!/bin/bash

mydir=$(dirname $0)

for PS in 128 256 512 1024 2048; do
    for DT in 800 900 1000 1250 1500 1750 2000 2500 5000; do
        for BW in 0.5 0.6 0.7 0.8 0.9; do
	    # Round bc output
	    CT=$(/bin/echo "$DT * $BW" | bc -l | sed -e 's/\..*//')

	    cat > do.gp <<EOF
#!/usr/bin/gnuplot

set terminal pdf
set output 'cdf-t$DT-s$PS-c$CT.pdf'

set grid
set xlabel 'Response-time (ms)'
set ylabel 'CDF'

plot \
  '< $mydir/log2dat.sh bw100mb-bdir-p10000/log-t$DT-s$PS-c$CT.txt | $mydir/dat2cdf.sh' u 1:2 t 'BW=100Mbps DT=$DT PS=$PS CT=$CT' w l lw 3, \
  '< $mydir/log2dat.sh bw10mb-bdir-p10000/log-t$DT-s$PS-c$CT.txt | $mydir/dat2cdf.sh' u 1:2 t 'BW=10Mbps DT=$DT PS=$PS CT=$CT' w l lw 3

EOF

	    gnuplot do.gp
	done
    done
done

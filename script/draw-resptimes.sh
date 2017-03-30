#!/bin/bash

mydir=$(dirname $0)

for PS in 128 256 512 1024 2048 4096; do
    for DT in 600 700 800 900 1000; do
	for BW in 0.5 0.6 0.7 0.8 0.9; do
	    # Round bc output
	    CT=$(/bin/echo "$DT * $BW" | bc -l | sed -e 's/\..*//')

cmdfile=draw-resptimes.gp
cat > $cmdfile <<EOF
#!/usr/bin/gnuplot

set terminal pdf
set output 'resptimes-t$DT-s$PS-c$CT.pdf'

set grid
set xlabel 'Packet send-time (s)'
set ylabel 'Response-time (ms)'

plot '< $mydir/log2dat.sh bw10mb-p1000/log-t$DT-s$PS-c$CT.txt' u (\$1/1000000):(\$2/1000) t 'BW=10mbps, T=$DT, PS=$PS, C=$CT', \
     '< $mydir/log2dat.sh bw100mb-p1000/log-t$DT-s$PS-c$CT.txt' u (\$1/1000000):(\$2/1000) t 'BW=1mbps, T=$DT, PS=$PS, C=$CT'

EOF
gnuplot $cmdfile

	done
    done
done

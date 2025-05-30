set terminal pdfcairo
set output "cdf.pdf"

set title "workload: client --to pcroom13 -C 2ms -F pcroom14 -C 2ms --skip 1,prob=0.1 -F pcroom15 -C 2ms -r 10 -n 50" font "Helvetica,10"
set xlabel "Response Time (ms)"
set ylabel "Percentile"
set grid
set yrange [0:1]

plot "< ./log2cdf.sh /tmp/ic2e.log"       using ($1/1000):2 with lines lw 2 title "normal condition", \
     "< ./log2cdf.sh /tmp/ic2e-netem.log" using ($1/1000):2 with lines lw 2 title "network impairment"

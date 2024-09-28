#!/bin/bash

echo "#### SSD ####"
echo "# SEQ"
fio --name SSD-SEQ --eta-newline=5s --filename=fio-tempfile.dat --rw=write --size=500m --io_size=10g --blocksize=1024k --ioengine=libaio --fsync=1 --iodepth=32 --direct=1 --numjobs=1 --runtime=60 --group_reporting
echo "# RND"
fio --name SSD-RND --eta-newline=5s --filename=fio-tempfile.dat --rw=randrw --size=500m --io_size=10g --blocksize=4k --ioengine=libaio --fsync=1 --iodepth=1 --direct=1 --numjobs=1 --runtime=60 --group_reporting


echo "#### HDD ####"
echo "# SEQ"
fio --name HDD-SEQ --eta-newline=5s --filename=/mnt/data/randreoli/fio-tempfile.dat --rw=write --size=500m --io_size=10g --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --fsync=1 --direct=1 --numjobs=1 --runtime=60 --group_reporting
echo "# RND"
fio --name HDD-RND --eta-newline=5s --filename=/mnt/data/randreoli/fio-tempfile.dat --rw=randrw --size=500m --io_size=10g --blocksize=4k --ioengine=libaio --fsync=1 --iodepth=1 --fsync=1 --direct=1 --numjobs=1 --runtime=60 --group_reporting


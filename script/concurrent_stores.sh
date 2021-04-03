#!/bin/bash

./client -s 1 -S 100000 &
./client -s 1 -S 100000 &
./client -s 1 -S 1000000 &
wait

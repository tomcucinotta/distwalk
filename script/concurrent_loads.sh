#!/bin/bash

./client -l 1 -S 1000 &
./client -l 1 -S 10000 &
./client -l 1 -S 100000 &
wait

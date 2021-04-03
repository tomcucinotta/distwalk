#!/bin/bash

../src/client -l 1 -S 1000 &
../src/client -l 1 -S 10000 &
../src/client -l 1 -S 100000 &
wait

#!/bin/bash

# Inter-arrival times to try
DTS=${DTS:-"800 900 1000 1250 1500 1750 2000 2500 5000"}

# Packet sizes to try
PSS=${PSS:-"128 256 512 1024 2048 4096 8192 16384"}

# Computational bandwidths to try
BWS=${BWS:-"0.5 0.6 0.7 0.8 0.9"}

# Number of packets in each run
PKTS=${PKTS:-10000}

# Server machine
SERVER=${SERVER:-theoden.retis}

# Client machine
CLIENT=${CLIENT:-$(hostname)}

# CPUs to be used on server
NODE_CPUS=${NODE_CPUS:-"0"}

# CPUs to be used on client
CLIENT_CPUS=${CLIENT_CPUS:-"2 3"}

SPEED=100

export DTS PSS BWS PKTS SERVER CLIENT NODE_CPUS CLIENT_CPUS SPEED

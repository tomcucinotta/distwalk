#!/bin/bash

. common.sh

node_bg -b tcp://:7894
client || true
client --to=tcp://127.0.0.1:7894
client --to=127.0.0.0 || true

#!/bin/bash

. common.sh

node_bg -b tcp://:7894
client || true
client --tcp=127.0.0.1:7894

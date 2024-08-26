#!/bin/bash

. common.sh

node_bg --tcp=7894
client || true
client --tcp=127.0.0.1:7894

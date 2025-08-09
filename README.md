DistWalk - Distributed end-to-end benchmarking tool for Linux
======================================================================
Copyright 2016-2025 by Tommaso Cucinotta (firstname dot lastname at santannapisa dot it)

DESCRIPTION
----------------------------------------------------------------------
DistWalk is a simple command-line tool useful to emulate distributed
processing scenarios, where a client submits requests to be processed
by one or more server nodes, in a distributed environment. The client
can be configured to send requests according to a pre-defined pattern
(e.g., periodically or exponentially distributed), where requests may
ask the server to perform processing for a time that is configurable
according to a pre-defined pattern (e.g., constant or exponentially
distributed processing time), or performing disk operations by reading
or writing a configurable amount of data.

The client provides, at the end of the experiment, all the end-to-end
processing times for all submitted requests.

The client establishes one or more TCP (or optionally, SSL/TLS)
connections to the server, which is capable of handling multiple client
connections via epoll(7).
The client can submit concurrent traffic by spawning multiple threads.
Furthermore, each thread can emulate different sessions where the
connection is closed and re-established for each new session.
The client, or the node, can forward a sequence of instructions
to N different nodes and await the response of M nodes (N>=M). 

More information on the objectives, motivations, design, architecture
and internals of DistWalk can be found in the paper:

R. Andreoli, T. Cucinotta. "DistWalk: a Distributed Workload Emulator,"
in Proceedings of the 25th IEEE international Symposium on
Cluster, Cloud and Internet Computing (IEEE CCGRID 2025), May 19-22,
2025, Tromsø, Norway.
See also: https://retis.santannapisa.it/~tommaso/papers/ccgrid25.php

COMPILING
----------------------------------------------------------------------
This program has been developed and tested on a Linux Ubuntu system,
versions from 16.xx to 21.xx. Therefore, please, use Linux.

In order to compile the client and the server, just type, from the
root folder:

  make

two executables are created:
- `src/dw_client`: the client program, try typing ./dw_client -h
- `src/dw_node`: the server program, try typing ./dw_node -h

For debug/development purposes, compile the executables, from the root folder:

  make debug

two executables are created:
- `src/dw_client_debug`: the client program with logging activated
- `src/dw_node_debug`: the server program with logging activated
- `src/dw_client_tsan`: the client program with logging and thread sanitizer activated
- `src/dw_node_tsan`: the server program with logging and thread sanitizer activated

DOCKER BUILD
----------------------------------------------------------------------
1. Build docker image:
```console
docker build -t distwalk .
```
2. Run docker container:
```console
docker run -it distwalk
```


EXAMPLES OF USE
----------------------------------------------------------------------
The classic and simplest scenario is the one of a client-server
scenario with client submitting periodically packets of a given
size, and expecting back responses of a different fixed size.

This example scenario is achieved launching on the server the simple
command:
```console
./dw_node
```
then launching on the client the following command, with which we are
submitting 10 requests asking 100us of computation, at a rate of 1000 pkt/s
```bash
./dw_client -n 10 -r 1000 -C 100us
```
```console
Configuration:
  clienthost=0.0.0.0:0
  serverhost=127.0.0.1:7891
  num_threads: 1
  num_pkts=10
  period=1000us
  waitspin=0
  rate=1000
  rate_step_secs=0
  pkt_size=1024 (+66 for headers)
  resp_size=512 (+66 with headers)
  min packet size due to header: send=20, reply=12
  max packet size: 16777216
  no_delay: 1
  num_sessions: 1
  use_per_session_output: 0
  num_conn_retries: 1 (retry_period: 200 ms)
  request template: ccmd COMPUTE(100us)->REPLY(512b,1)
t: 176 us, elapsed: 164 us, req_id: 0, thr_id: 0, sess_id: 0
t: 1213 us, elapsed: 137 us, req_id: 1, thr_id: 0, sess_id: 0
t: 2214 us, elapsed: 163 us, req_id: 2, thr_id: 0, sess_id: 0
t: 3213 us, elapsed: 127 us, req_id: 3, thr_id: 0, sess_id: 0
t: 4210 us, elapsed: 127 us, req_id: 4, thr_id: 0, sess_id: 0
t: 5210 us, elapsed: 130 us, req_id: 5, thr_id: 0, sess_id: 0
t: 6211 us, elapsed: 144 us, req_id: 6, thr_id: 0, sess_id: 0
t: 7213 us, elapsed: 133 us, req_id: 7, thr_id: 0, sess_id: 0
t: 8303 us, elapsed: 125 us, req_id: 8, thr_id: 0, sess_id: 0
t: 9212 us, elapsed: 127 us, req_id: 9, thr_id: 0, sess_id: 0
```

The following command spawns 4 threads submitting concurrently
requests to the server `a.b.c.d` (each thread submits 5000 requests needing
a 1ms of processing time each, at a rate of 250 pkt/s):
```bash
  ./dw_client --to a.b.c.d --nt 4 -n 5000 -r 250 -C 1000
```
The following command spawns 3 threads, with each of them using 10
sessions to submit the 5000 packets as in the above command, so each
session will send 500 requests at a rate of 250 pkt/s (at the end of
each session, each client thread closes the connection and establishes
a new connection for the subsequent session)
```bash
  ./dw_client --nt 3 --ns 10 -n 5000 -r 250 -C 1000
```

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

The client establishes one or more TCP connections to the server,
which is capable of handling multiple client connections via epoll(7).
The client can submit concurrent traffic by spawning multiple threads.
Furthermore, each thread can emulate different sessions where the
connection is closed and re-established for each new session.
The client, or the node, can forward a sequence of instructions
to N different nodes and await the response of M nodes (N>=M). 

More information on the objectives, motivations, design, architecture
and internals of DistWalk can be found in the paper:

R. Andreoli, T. Cucinotta. "DistWalk: a Distributed Workload Emulator,"
(to appear) in Proceedings of the 25th IEEE international Symposium on
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

DOCUMENTATION
----------------------------------------------------------------------
dw_node supports the following command-line options:

```  -b, --bind-addr=[tcp|udp:[//]][host][:port]```

Set the bind name or IP address, port, and communication protocol. All
three parts of the argument are optional:
- if the protocol is not specified, then TCP is assumed by default
- if the host is not specified, then localhost is assumed by default
- if the port is not specified, then 7891 is assumed by default

Not using this option, is equivalent to calling dw_node with `-b tcp://localhost:7891`.

```  --backlog-length=n, --bl=n```

Set the maximum number of pending incoming connections, for each bound
socket, i.e., the argument used when calling listen(). See also the
accept mode option described above.

```  --no-delay=0|1, --nd=0|1```

Enable or disable the TCP_NODELAY socket option (enabled by default).

```  --nt=n, --num-threads=n```

Set the number of worker threads (defaults to one worker thread).

```  -c, --thread-affinity=auto|cX,cZ[,cA-cD[:step]]```

Enable thread-to-core pinning through affinity masks. The mask is specified with
the usual core-list syntax, as a comma-separated list of core ranges, with the
optional use of a colon followed by a core step in a specified range, if desired.
If the number of worker threads (see --nt) is higher than the cores in the affinity
list, then the list is reused circularly from the beginning (this allows for pinning
2, 3 or as many threads as desired to a single physical core)/
The special value "auto" sets and affinity of 0-n, where n is equal to the number
of specified threads minus one. By default, no affinity is set for worker threads.

```  --sched-policy=other[:nice]|rr:rtprio|fifo:rtprio|dl:runtime_us,dline_us```

Set the scheduling policy (defaults to other), and its parameters:
- `other`: use the default Linux SCHED_OTHER scheduler, where the optional nice parameter
  can be used to customize the niceness level
- `rr`, `fifo`: use the SCHED_RR or SCHED_FIFO real-time scheduling classes, with the
  specified real-time priority number, in the range 1-99
- `dl`: use the SCHED_DEADLINE EDF/CBS-based real-time scheduler available in the
  mainline Linux kernel, using the specified reservation runtime and deadline, which
  is set equal to the reservation period.

```  --wait-spin, --ws```

Tell each worker thread to perform a busy-wait loop, till the next incoming request
on any of the monitored sockets, instead of sleeping. This allows the worker threads
to be always ready, so to save wake-up from idle, and context switch overheads, thus
it is useful in scenarios seeking extremely low latency. However, it causes each
worker thread to take 100% of a CPU, regardless on the amount of traffic hitting it.

```  -a, --accept-mode=child|shared|parent```

Set the server accept mode:
- `child`: each worker thread calls accept() independently from its own
  bound socket, availing of the REUSEPORT socket option
- `shared`: all worker threads accept() from the same socket, that is
  created and bound just once, then used by all of them
- `parent`: only the parent accept()s connection on a single bound socket,
  then connections are handed over to worker threads internally

```  -p, --poll-mode=epoll|poll|select```

Set the poll mode (defaults to epoll) used by worker threads for monitoring their
sockets:
- `select`: use the select() system call
- `poll`: use the poll() system call
- `epoll`: use the epoll() system call (default)

```  -s, --storage=path/to/storage/file```

Set the path to the file to be used for LOAD/STORE operations. On STORE, the
file is automatically expanded in size, up to the maximum size specified with -m.
Note that the file location allows for determining also the type of storage
one wants to use, depending on whether the specified pathname is on a HDD or SSD
drive, for example.

```  -m, --max-storage-size=nbytes```

Set the maximum size for the storage file used for LOAD/STORE operations.
When the file offset is automatically increased and it reaches this value,
it undergoes a rewind to 0. See also the -s option.

```  --odirect```

Enable direct disk access for LOAD and STORE operations (bypass read/write OS caches).

```  --sync=msec```

Periodically sync the written data on disk, issueing a fsync() system call on the
storage file.

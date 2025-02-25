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

NODE/SERVER DOCUMENTATION
----------------------------------------------------------------------
The server `dw_node` supports the following command-line options:

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

```  --usage, -h, --help```

Show a short help message.

CLIENT DOCUMENTATION
----------------------------------------------------------------------
The client `dw_client` supports the following command-line options:

```  --to=[tcp|udp:[//]][host][:port]```

Set the target node host, port and protocol. All elements can be specified or not, see the description of the -F command-line option above for details.

```  -b, --bind-addr=host[:port]|:port```

Set explicitly the bind address or name, and the bind port, for the client.

```  -n, --num-pkts=n|auto```

Set the number of requests sent by each thread (across all sessions).

```  --num-sessions=n, --ns=n```

Set the number of sessions each client thread establishes with the (initial) distwalk node. The overall number of requests to be submitted, specified with `-n`, is evenly split across the various sessions. If this option is not used, each thread submits its overall number of requests within a single session.

```  --per-session-output, --pso```

Let the client output the response times obtained for each session, at the end of the session, rather than at the end of the program. this implies some extra delay between sessions, but it requires the client to save on the needed memory.

```  --ps=nbytes|prob:field=val[,field=val]```

Set the payload size of the sent requests, or their probability distribution (see below for details on how to specify distributions).

```  --num-threads=n, --nt=n```

Set the number of client threads, corresponding to parallel sessions that are opened with the (initial) distwalk node, each submitting the overall number of requests as specified with `-n`. If this option is not used, only one thread will be submitting requests.

```  -p, --period=usec|prob:field=val[,field=val]``

Set the inter-spacing period to be used by each sender thread, between submitting two consecutive requests.

```  --rate-step-secs=sec, --rss=sec```

Set the duration of each rate-step.

```  -r, --rate=npkt```

Set the packet sending rate (in pkts per sec).

```  --stag-send```

Enable staggered send among sender threads. This allows to avoid stressing the server with all requests hitting it at the same time.

```  --conn-times```

Add also the connect() times to the final report output by the client.

```  --no-delay=0|1, --nd=0|1```

Enable or disable the TCP_NODELAY socket option (default is enabled).

```  --non-block```

Tell each client thread to perform a busy-wait loop instead of waiting, till the point in time in which the next request is to be sent.
This id one by setting the socket in SOCK_NONBLOCK mode.

```  --wait-spin, --ws```

Tell each client thread to perform a busy-wait loop instead of waiting, till the point in time in which the next request is to be sent.

```  -C, --comp-time=usec|prob:field=val[,field=val]```

Add to the sequence of operations submitted per-request to the server,
a COMPUTE operation, with the specified processing time, or processing
time distribution (see specifying distributions below).

```  -L, --load-data=nbytes|prob:field=val[,field=val]```

Add a LOAD operation to the submitted per-request operations list,
with the specified data payload size, in bytes (see below for details
on how to specify distributions).

```  --load-offset=nbytes|prob:field=val[,field=val]```

Set the offset to be used, or the distribution it has to be drawn from,
for the subsequent LOAD operations.

```  -S, --store-data=nbytes|prob:field=val[,field=val][,nosync]```

Add to the per-request operations list to be submitted, a STORE operation, specifying its payload size in bytes, or its distribution (see below for details on how to specify distributions).

```  --store-offset=nbytes|prob:field=val[,field=val]```

Set the offset value, or its distribution, for the subsequent STORE operations.

```  -F, --forward=ip:port[,ip:port,...][,timeout=usec][,retry=n][,branch][,nack=n]```

Add a FORWARD operation to the submitted per-request operations list,
specifying the ip:port to forward to, the timeout to wait for, and the
number of retries in case of failure to receive the REPLY to the
FORWARD.  This option allows also to specify multiple ip:port
receivers. In this case, the FORWARD is performed in parallel to all
the specified receivers, and by default all of their REPLY responses
are needed, before moving on with processing the rest of the
operations list.  However, the `nack=n` option allows for customizing
the number of acknowledgements to wait for, before moving on. For
example, it is possible to FORWARD to 3 different nodes, and wait for
just 1 or 2 of their REPLY responses, to move on. This is useful to
emulate the typical behavior of distributed quorum-based protocols.

Normally, when multiple ip:port are specified, the FORWARD messages
are sent identical to all the peers, and are extracted starting from
the operation following the FORWARD, to the matching REPLY.  However,
if the `branch` option is used, then different messages can be
forwarded to the different peers, and they have to be specified each
as a FORWARD operation matching its own REPLY. For example:

  ```-F ip1:p1,branch -C 10ms -R -F ip2:p2,branch -C 20ms -R```

```  -R, --rs[=nbytes|prob:field=val[,field=val]]```

Add to the list of per-request operations to be submitted, a REPLY command. Optionally, specify the payload size, or the distribution its value has to be drawn from (see below for details on how to specify distributions).

```  --retry-num=n```

Set the number of connection retries in case of failure.

```  --retry-period=msec```

Set the interval between subsequent connection retries.

```  -s, --skip=n[,prob=val]```

Skip the next `n` commands (with probability val, defaults to 1.0 if unspecified).

```  -f, --script-filename=path/to/file```

Read the sequence of commands to be submitted per-request operations
list, as well as other `dw_client` options, from the specified script
file, as though its contents were added to the command-line in the
point where this option is used.  This can be intermixed with other
regular command-line options.

```  --usage, -h, --help```

Show a short help message.

Many parameters in the `dw_client` command-line can be specified as samples to be drawn from a probability distribution. The tool has a versatile syntax allowing for a wide range of specifications:
- constant values: just use a number, but consider using 'k' or 'm' suffixes, to shorten thousands and millions, respectively; for time quantities, the default time-unit is in microseconds, but the suffixes 'ns', 'us', 'ms' or 's' allow for a more friendly syntax;
  for example, 1500 requests can be specified as `-n 1500` or `-n 1.5k`; a COMPUTE operation with processing time of 10ms (= 10000us) can be specified as `-C 10000`, `-C 10000us`, `-C 10ms`, or even `-C 0.01s`;
- probability distributions: the syntax is prob:value[,param=value[,...]]; different parameters are supported depending on the distribution:
  - `exp:avg-val[,min=a][,max=b]`: samples are drawn from an exponential distribution with the specified average; if the optional min= and/or max= specifiers are used, then the distribution is truncated on the left and/or right, respectively;
  - `unif:min=a,max=b`: samples are drawn from a uniform between a and b;
    for example, a request inter-arrival time uniformly distributed between 10ms and 20ms, can be specified as: `-p unif:min=10ms,max=20ms`;
  - `norm:avg-val,std=std-val`: samples are drawn from a Gaussian distribution with the specified average and standard deviation; if the optional min= and/or max= specifiers are used, then the distribution is truncated on the left and/or right, respectively;
  - `lognorm:avg-val,std=std-val[,xval=avg-xval][,xstd=avg-xstd]`: samples are drawn from a LogNormal distribution with the specified average and standard deviation; if preferred, parameters of the supporing Gaussian distribution can be specified with the xavg and xstd parameters; the distribution can also be truncated using the usual min= and max= specifiers;
  - `gamma:avg-val[,std=std-val][,k=k-val][,scale=s-val]`: samples are drawn from a Gamma distribution with the specified average and standard deviation, or, if preferred, with the specified k and scale values; the distribution can be truncated with the min= and max= specifiers;
  - `aseq:min=a,max=b[,step=s-val]`: samples picked from an arithmetic progression starting at a, and increasing by 1 each time, or by the specified step s-val each time, up to the maximum value b; in addition to ramp-up scenarios, also ramp-down ones can be specified, specifying a negative step;
    for example, a ramp-up workload starting at 100 reqs/s, and stepping up every second bu 10 reqs/s, up to 1000 reqs/s, is specified as: `-r seq:min=100,max=1000,step=10`;
  - `gseq:min=a,max=b[,step-s-val]`: samples picked from a geometric progression starting at a, and multiplying by the specified step s-val each time, up to the maximum value b; the multiplier can be greater or lower than one, resulting in either increasing or decreasing progressions;
  - `file:path/to/file[,sep=sep-char][,col=col-val][,unit=]`: samples are loaded from the specified column of the specified file (defaults to the first column), where columns on each line are assumed to be separated by the specified separator character (defaults to a comma); an optional unit specifier applies to all read values, causing their automatic rescaling;
    for example, to load inter-arrival times and execution times from the 2nd and 4th column of a data.csv file, expressed in ms, use: `-C file:data.csv,col=2,unit=ms -p file:data.csv,col=4,unit=ms`

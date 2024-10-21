#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <argp.h>

#include "dw_debug.h"
#include "distrib.h"
#include "message.h"
#include "connection.h"
#include "timespec.h"
#include "ccmd.h"
#include "address_utils.h"

__thread char thread_name[16];

int use_wait_spinning = 0;

ccmd_t* ccmd = NULL; // Ordered chain of commands

unsigned int default_compute_us = 1000;

pd_spec_t send_pkt_size_pd = { .prob = FIXED, .val = 1024, .std = NAN, .min = NAN, .max = NAN };
pd_spec_t send_period_us_pd = { .prob = FIXED, .val = 100000, .std = NAN, .min = NAN, .max = NAN };
pd_spec_t send_rate_pd = { .prob = FIXED, .val = 10, .std = NAN, .min = NAN, .max = NAN };
pd_spec_t load_offset_pd = { .prob = FIXED, .val = -1, .std = NAN, .min = NAN, .max = NAN };
pd_spec_t store_offset_pd = { .prob = FIXED, .val = -1, .std = NAN, .min = NAN, .max = NAN };

unsigned long default_resp_size = 512;

int no_delay = 1;
int use_per_session_output = 0;
int conn_retry_num = 1;
int conn_retry_period_ms = 200;
int conn_nonblock = 0;
int conn_times = 0;

#define MAX_THREADS 256
pthread_t sender[MAX_THREADS];
pthread_t receiver[MAX_THREADS];


#define TCPIP_HEADERS_SIZE 66
#define MIN_SEND_SIZE (sizeof(message_t) + 2 * sizeof(command_t))
#define MIN_REPLY_SIZE sizeof(message_t)

#define MAX_PKTS 1000000
#define MAX_RATES 1000000

clockid_t clk_id = CLOCK_REALTIME;
int clientSocket[MAX_THREADS];
long *usecs_send[MAX_THREADS];
long *usecs_elapsed[MAX_THREADS];
// abs start-time of the experiment
struct timespec ts_start;

unsigned long num_pkts = 1;

unsigned int ramp_step_secs = 0;   // used with --rate

proto_t proto = TCP;

struct sockaddr_in serveraddr;
struct sockaddr_in myaddr;

unsigned long pkts_per_session;

typedef struct {
    int thread_id;
    int conn_id;
    int first_pkt_id;
    int num_send_pkts;
} thread_data_t;

int idx(int pkt_id) {
    int val = use_per_session_output ? pkt_id % pkts_per_session : pkt_id;
    assert(val < MAX_PKTS);
    return val;
}

void *thread_sender(void *data) {
    thread_data_t *p = (thread_data_t *)data;

    sprintf(thread_name, "sendw-%d", p->thread_id);
    sys_check(prctl(PR_SET_NAME, thread_name, NULL, NULL, NULL));

    int thread_id = p->thread_id;
    int first_pkt_id = p->first_pkt_id;
    int num_send_pkts = p->num_send_pkts;
    struct timespec ts_now;

    clock_gettime(clk_id, &ts_now);
    pd_init(time(NULL));

    message_t *m;
    conn_info_t *conn = conn_get_by_id(p->conn_id);

#ifdef DW_DEBUG
    ccmd_log(ccmd);
#endif

    for (int i = 0; i < num_send_pkts; i++) {
        m = conn_send_message(conn);
        ccmd_dump(ccmd, m);

        /* remember time of send relative to ts_start */
        struct timespec ts_send;
        clock_gettime(clk_id, &ts_send);
        int pkt_id = first_pkt_id + i;
        usecs_send[thread_id][idx(pkt_id)] = ts_sub_us(ts_send, ts_start);
        // mark corresponding elapsed value as 0, i.e., non-valid (in case we
        // don't receive all packets back)
        usecs_elapsed[thread_id][idx(pkt_id)] = 0;
        /*---- Issue a request to the server ---*/
        m->req_id = pkt_id;
        m->req_size = pd_sample(&send_pkt_size_pd);

        dw_log("sending %u bytes...\n", m->req_size);
        assert(m->req_size <= BUF_SIZE);

#ifdef DW_DEBUG
        msg_log(m, "Sending msg: ");
#endif
        if (!conn_start_send(conn, conn->target)) {
            fprintf(stderr,
                    "Forcing premature termination of sender thread while "
                    "attempting to send pkt %d\n",
                    pkt_id);
            break;
        }

        if (ramp_step_secs != 0 && pkt_id > 0) {
            int step_prev =
                usecs_send[thread_id][idx(pkt_id - 1)] / 1000000 / ramp_step_secs;
            int step =
                usecs_send[thread_id][idx(pkt_id)] / 1000000 / ramp_step_secs;
            int rate;
            while (step_prev++ < step) {
                int old_rate = 1000000.0 / send_period_us_pd.val;
                rate = pd_sample(&send_rate_pd);
                send_period_us_pd.val = 1000000.0 / rate;
                if (rate != old_rate) {
                    dw_log("pkt_id: %d, old_rate: %d, rate: %d\n", pkt_id, old_rate, rate);
                }
            }
        }

        unsigned long period_ns = pd_sample(&send_period_us_pd) * 1000.0;
        dw_log("period_ns=%lu\n", period_ns);
        struct timespec ts_delta =
            (struct timespec) { period_ns / 1000000000, period_ns % 1000000000 };

        ts_now = ts_add(ts_now, ts_delta);

        if (use_wait_spinning) {
            struct timespec ts;
            do {
                clock_gettime(clk_id, &ts);
            } while (ts_leq(ts, ts_now));
        } else {
            sys_check(clock_nanosleep(clk_id, TIMER_ABSTIME, &ts_now, NULL));
        }
    }

    dw_log("Sender thread terminating\n");

    return 0;
}

int connect_retry(int thread_id, int sess_id) {
    int rv = 0;
    int conn_retry;
    for(conn_retry = 1; conn_retry <= conn_retry_num; conn_retry++) {
        /*---- Create the socket. The three arguments are: ----*/
        /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in
         * this case) */
        if (proto == TCP) {
            clientSocket[thread_id] = socket(PF_INET, SOCK_STREAM | (conn_nonblock ? SOCK_NONBLOCK : 0), 0);

            sys_check(setsockopt(clientSocket[thread_id], IPPROTO_TCP,
                                 TCP_NODELAY, (void *)&no_delay,
                                 sizeof(no_delay)));
        } else {
            clientSocket[thread_id] = socket(PF_INET, SOCK_DGRAM | (conn_nonblock ? SOCK_NONBLOCK : 0), 0);
        }

        dw_log("Binding to %s:%d\n", inet_ntoa(myaddr.sin_addr),
               ntohs(myaddr.sin_port));


        if (ntohs(myaddr.sin_port) != 0) {
            int val = 1;
            sys_check(setsockopt(clientSocket[thread_id], SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(val)));
        }

        /*---- Bind the address struct to the socket ----*/
        sys_check(bind(clientSocket[thread_id], (struct sockaddr *)&myaddr,
                       sizeof(myaddr)));

        /*---- Connect the socket to the server using the address struct
         * ----*/
        dw_log("Connecting to %s:%d (sess_id=%d, retry=%d) ...\n", inet_ntoa((struct in_addr) {serveraddr.sin_addr.s_addr}), ntohs(serveraddr.sin_port), sess_id, conn_retry);

        if ((rv = connect(clientSocket[thread_id], (struct sockaddr *)&serveraddr, sizeof(serveraddr))) == 0 || (rv == -1 && errno == EINPROGRESS)) {
            rv = 0;
            break;
        } else {
            close(clientSocket[thread_id]);
            usleep(conn_retry_period_ms * 1000);
        }
    }
    return rv;
}

void *thread_receiver(void *data) {
    int thread_id = (int)(unsigned long)data;

    sprintf(thread_name, "recvw-%d", thread_id);
    sys_check(prctl(PR_SET_NAME, thread_name, NULL, NULL, NULL));

    message_t *m = NULL;
    int recv = 0;

    for (int i = 0; i < num_pkts; i++) {
        thread_data_t thr_data;
        if (i % pkts_per_session == 0) {
            struct timespec ts1, ts2;
            if (conn_times)
                clock_gettime(CLOCK_MONOTONIC, &ts1);
            int rv = connect_retry(thread_id, i / pkts_per_session);
            if (conn_times)
                clock_gettime(CLOCK_MONOTONIC, &ts2);
            // check if connection succeeded
            if (rv != 0) {
                close(clientSocket[thread_id]);
                fprintf(stderr, "Connection to %s:%d failed: %s\n", inet_ntoa((struct in_addr) {serveraddr.sin_addr.s_addr}), ntohs(serveraddr.sin_port), strerror(errno));
                exit(EXIT_FAILURE);
            }

            if (conn_times)
                printf("conn_time: %ld us, req_id: %d, thr_id: %d, sess_id: %d\n",
                       (ts2.tv_sec-ts1.tv_sec)*1000000+(ts2.tv_nsec-ts1.tv_nsec)/1000,
                       i, thread_id, i / (int)pkts_per_session);

            /* spawn sender once connection is established */

            int conn_id = conn_alloc(clientSocket[thread_id], serveraddr, proto);
            check(conn_id != -1, "conn_alloc() failed, consider increasing MAX_CONNS");
            conn_set_status_by_id(conn_id, READY);

            // TODO (?) thr_data is allocated in the stack and reused for every thread, possible (but completly improbable) race condition
            thr_data.thread_id = thread_id;
            thr_data.conn_id = conn_id;
            thr_data.first_pkt_id = i,
            thr_data.num_send_pkts = pkts_per_session;
            sys_check(pthread_create(&sender[thread_id], NULL, thread_sender,
                                  (void *)&thr_data));
        }

        /*---- Read the message from the server into the buffer ----*/
        // TODO: support receive of variable reply-size requests
        conn_info_t *conn = conn_get_by_id(thr_data.conn_id);

        do {
            if (m == NULL)
                recv = conn_recv(conn);
            m = conn_next_message(conn);
        } while (recv > 0 && m == NULL);

        if (m == NULL) {
            printf("Error: cannot read received message\n");
            unsigned long skip_pkts =
                pkts_per_session - ((i + 1) % pkts_per_session);
            printf("Fast-forwarding i by %lu pkts\n", skip_pkts);
            i += skip_pkts;
            goto skip;

        }

        unsigned pkt_id = m->req_id;

#ifdef DW_DEBUG
        msg_log(m, "received message: ");
#endif

        if (m->status != 0) {
            dw_log("REPLY reported an error\n");
            goto skip;
        }

        struct timespec ts_now;
        clock_gettime(clk_id, &ts_now);
        unsigned long usecs = (ts_now.tv_sec - ts_start.tv_sec) * 1000000 +
                              (ts_now.tv_nsec - ts_start.tv_nsec) / 1000;
        usecs_elapsed[thread_id][idx(pkt_id)] =
            usecs - usecs_send[thread_id][idx(pkt_id)];
        dw_log("thread_id: %d sess_id: %ld req_id %u elapsed %ld us\n", thread_id, pkt_id / pkts_per_session, pkt_id,
               usecs_elapsed[thread_id][idx(pkt_id)]);

    skip:
        if ((i + 1) % pkts_per_session == 0) {
            dw_log(
                "Session is over (after receive of pkt %d), closing socket\n",
                i);
            close(clientSocket[thread_id]);
            conn_free(thr_data.conn_id);
            if (use_per_session_output) {
                int first_sess_pkt = i - (pkts_per_session - 1);
                int sess_id = i / pkts_per_session;
                for (int j = 0; j < pkts_per_session; j++) {
                    int pkt_id = first_sess_pkt + j;
                    // if we abruptly terminated the session, the send timestamp
                    // of packets never sent will stay at 0
                    if (usecs_send[thread_id][idx(pkt_id)] != 0)
                        printf(
                            "t: %ld us, elapsed: %ld us, req_id: %d, thr_id: "
                            "%d, sess_id: %d\n",
                            usecs_send[thread_id][idx(pkt_id)],
                            usecs_elapsed[thread_id][idx(pkt_id)], pkt_id,
                            thread_id, sess_id);
                }
                // make sure we reset the send timestamp and elapsed array to
                // zeros for the next session
                memset(&usecs_send[thread_id][0], 0, sizeof(usecs_send[thread_id][0]) * MAX_PKTS);
                memset(&usecs_elapsed[thread_id][0], 0, sizeof(usecs_send[thread_id][0]) * MAX_PKTS);
            }
            dw_log("Joining sender thread\n");
            pthread_join(sender[thread_id], NULL);
        }
    }

    if (!use_per_session_output) {
        for (int i = 0; i < num_pkts; i++) {
            int sess_id = i / pkts_per_session;
            printf(
                "t: %ld us, elapsed: %ld us, req_id: %d, thr_id: %d, sess_id: "
                "%d\n",
                usecs_send[thread_id][i], usecs_elapsed[thread_id][idx(i)], i,
                thread_id, sess_id);
        }
    }

    dw_log("Receiver thread terminating\n");
    return 0;
}

int script_parse(char *fname, struct argp_state *state);

enum argp_client_option_keys {
    HELP = 'h',
    USAGE = 0x100,
    NUM_PKTS = 'n',
    PERIOD = 'p',
    RATE = 'r',
    COMP_TIME = 'C',
    STORE_DATA = 'S',
    LOAD_DATA = 'L',
    STORE_OFFSET = 0x101,
    LOAD_OFFSET = 0x102,
    SKIP_CMD = 's',
    FORWARD_CMD = 'F',
    SCRIPT_FILENAME = 'f',
    BIND_ADDR ='b',

    WAIT_SPIN = 0x200,
    RATE_STEP_SECS,
    SEND_REQUEST_SIZE,
    RESPONSE_SIZE,
    NO_DELAY,
    NUM_THREADS,
    NUM_SESSIONS,
    PER_SESSION_OUTPUT,
    TO_OPT_ARG,
    CONN_RETRY_NUM,
    CONN_RETRY_PERIOD,
    CONN_TIMES,
    CONN_NONBLOCK,
};

struct argp_client_arguments {
    int num_sessions;
    int num_threads;
    char clienthostport[MAX_HOSTPORT_STRLEN];
    char nodehostport[MAX_HOSTPORT_STRLEN];
    pd_spec_t last_resp_size;
};

static struct argp_option argp_client_options[] = {
    // long name, short name, value name, flag, description
    { "bind-addr",          BIND_ADDR,              "host[:port]|:port",                          0, "Set client bindname and bindport"},
    { "to",                 TO_OPT_ARG,             "[tcp|udp:[//]][host][:port]",                0, "Set distwalk target node host, port and protocol"},
    { "num-pkts",           NUM_PKTS,               "n|auto",                                     0, "Number of packets sent by each thread (across all sessions"},
    { "period",             PERIOD,                 "usec|prob:field=val[,field=val]",            0, "Inter-send period for each thread"},
    { "rate",               RATE,                   "npkt",                                       0, "Packet sending rate (in pkts per sec)"},
    { "wait-spin",          WAIT_SPIN,               0,                                           0, "Spin-wait instead of sleeping till next sending time"},
    { "ws",                 WAIT_SPIN,               0,  OPTION_ALIAS },
    { "rate-step-secs",     RATE_STEP_SECS,         "sec",                                        0, "Duration of each rate-step"},
    { "rss",                RATE_STEP_SECS,         "n", OPTION_ALIAS},
    { "comp-time",          COMP_TIME,              "usec|prob:field=val[,field=val]",            0, "Per-request processing time"},
    { "store-offset",       STORE_OFFSET,           "nbytes|prob:field=val[,field=val]",          0, "Per-store file offset"},
    { "store-data",         STORE_DATA,             "nbytes|prob:field=val[,field=val][,nosync]", 0, "Per-store data payload size"},
    { "load-offset",        LOAD_OFFSET,            "nbytes|prob:field=val[,field=val]",          0, "Per-load file offset"},
    { "load-data",          LOAD_DATA,              "nbytes|prob:field=val[,field=val]",          0, "Per-load data payload size"},
    { "skip",               SKIP_CMD,               "n[,prob=val]",                               0, "Skip the next n commands (with probability val, defaults to 1.0)"},
    { "forward",            FORWARD_CMD,            "ip:port[,ip:port,...][,nack=n][,timeout=n][,retry=n]", 0, "Send a number of FORWARD message to the ip:port list, wait for n replies"},
    { "send-pkt-size",      SEND_REQUEST_SIZE,      "nbytes|prob:field=val[,field=val]",          0, "Set payload size of sent requests"},
    { "ps",                 SEND_REQUEST_SIZE,      "nbytes|prob:field=val[,field=val]", OPTION_ALIAS},
    { "resp-pkt-size",      RESPONSE_SIZE,          "nbytes|prob:field=val[,field=val]",          0, "Set payload size of received responses"},
    { "rs",                 RESPONSE_SIZE,          "nbytes|prob:field=val[,field=val]", OPTION_ALIAS},
    { "num-threads",        NUM_THREADS,            "n",                                          0, "Number of threads dedicated to communication" },
    { "nt",                 NUM_THREADS,            "n", OPTION_ALIAS },
    { "num-sessions",       NUM_SESSIONS,           "n",                                          0, "Number of sessions each thread establishes with the (initial) distwalk node"},
    { "ns",                 NUM_SESSIONS,           "n", OPTION_ALIAS},      
    { "retry-num",          CONN_RETRY_NUM,         "n",                                          0, "Number of connection retries to the (initial) distwalk node in case of failure"},
    { "retry-period",       CONN_RETRY_PERIOD,      "msec",                                       0, "Interval between subsequent connection retries to the (initial) distwalk node"},
    { "conn-times",         CONN_TIMES,              0,                                           0, "Output also connect() times"},
    { "non-block",          CONN_NONBLOCK,           0,                                           0, "Set SOCK_NONBLOCK on connect()"},
    { "no-delay",           NO_DELAY,             "0|1",                                          0, "Set value of TCP_NODELAY socket option"},
    { "nd",                 NO_DELAY,             "0|1", OPTION_ALIAS },
    { "per-session-output", PER_SESSION_OUTPUT,       0,                                          0, "Output response times at end of each session (implies some delay between sessions but saves memory)" },
    { "pso",                PER_SESSION_OUTPUT,       0, OPTION_ALIAS },
    { "script-filename",    SCRIPT_FILENAME,        "path/to/file",                               0, "Continue reading commands from script file (can be intermixed with regular options)"},
    { "help",               HELP,                    0,                                           0, "Show this help message", 1 },
    { "usage",              USAGE,                   0,                                           0, "Show a short usage message", 1 },
    { 0 }
};

static error_t argp_client_parse_opt(int key, char *arg, struct argp_state *state) {
        /* Get the input argument from argp_parse, which we
        know is a pointer to our arguments structure. */
    struct argp_client_arguments *arguments = state->input;

    switch(key) {
    case ARGP_KEY_INIT: // Default values
        strcpy(arguments->clienthostport, "0.0.0.0:0");
        strcpy(arguments->nodehostport, DEFAULT_ADDR ":" DEFAULT_PORT);

        arguments->num_sessions = 1;
        arguments->num_threads = 1;
        arguments->last_resp_size = pd_build_fixed(default_resp_size);
        break;
    case HELP:
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
        break;
    case USAGE:
        argp_state_help(state, state->out_stream, ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK);
        break;
    case BIND_ADDR:
        check(strlen(arg) < MAX_HOSTPORT_STRLEN, "Too long host:port argument to %c option", BIND_ADDR);
        strcpy(arguments->clienthostport, arg);
        break;
    case TO_OPT_ARG:
        check(strlen(arg) < MAX_HOSTPORT_STRLEN, "Too long host:port argument to --to option");
        addr_proto_parse(arg, arguments->nodehostport, &proto);
        break;
    case NUM_PKTS:
        if (strcmp(arg, "auto") == 0)
            num_pkts = 0;
        else
            num_pkts = atoi(arg);
        break;
    case PERIOD:
        check(pd_parse(&send_period_us_pd, arg), "Wrong period specification");
        break;
    case RATE:
        check(pd_parse(&send_rate_pd, arg), "Wrong rate specification");
        send_period_us_pd = pd_build_fixed(1000000.0 / pd_sample(&send_rate_pd));
        break;
    case WAIT_SPIN:
        use_wait_spinning = 1;
        break;
    case RATE_STEP_SECS:
        ramp_step_secs = atoi(arg);
        break;
    case COMP_TIME: {
        pd_spec_t val;
        check(pd_parse(&val, arg), "Wrong computation time specification");
        ccmd_add(ccmd, COMPUTE, &val);
        break; }
    case LOAD_OFFSET: {
        check(pd_parse(&load_offset_pd, arg), "Wrong load-offset specification");
        break; }
    case STORE_OFFSET: {
        check(pd_parse(&store_offset_pd, arg), "Wrong store-offset specification");
        break; }
    case STORE_DATA: {        
        uint8_t sync = 1;
        char* reserve;
        char *tok = strtok_r(arg, ",", &reserve);
        while (tok != NULL) {
            if (strncmp(tok, "nosync", 6) == 0) {
                sync = 0;
            } else if (strncmp(tok, "sync", 4) == 0) {
                sync = 1;
            } else {
                pd_spec_t val;
                check(pd_parse(&val, arg), "Wrong store data size specification");
                ccmd_add(ccmd, STORE, &val);
                ccmd_last_action(ccmd)->pd_val2 = store_offset_pd;
            }

            tok = strtok_r(NULL, ",", &reserve);
        }

        ccmd_last_action(ccmd)->store.wait_sync = sync;

        break; }
    case LOAD_DATA: {
        pd_spec_t val;
        check(pd_parse(&val, arg), "Wrong load data size specification");
        ccmd_add(ccmd, LOAD, &val);
        ccmd_last_action(ccmd)->pd_val2 = load_offset_pd;
        break; }
    case SKIP_CMD: {
        pd_spec_t val = pd_build_fixed(1.0);
        int n_skip = -1;
        char *tok;
        while ((tok = strsep(&arg, ",")) != NULL) {
            if (sscanf(tok, "%d", &n_skip) == 1)
                check(n_skip >=1, "arg to --skip must be a positive integer");
            else if (sscanf(tok, "prob=%lf", &val.val) == 1)
                check(val.val > 0.0 && val.val <= 1.0, "prob= in --skip needs a value > 0 and <= 1.0\n");
            else {
                fprintf(stderr, "Wrong syntax for --skip args\n");
                exit(EXIT_FAILURE);
            }
        }
        check(n_skip != -1, "--skip needs a positive integer as arg\n");
        ccmd_node_t *p = ccmd_add(ccmd, PSKIP, &val);
        p->n_skip = n_skip;
        break; }
    case FORWARD_CMD: {
        struct sockaddr_in fwd_addr;
        command_type_t fwd_type = FORWARD;
        pd_spec_t val = pd_build_fixed(default_resp_size);

        int n_ack = 0;
        int timeout_us = 500000;
        int retry_num = 0;
        int i = 0;

        char* reserve;
        char *tok = strtok_r(arg, ",", &reserve);
        while (tok != NULL) {
            if (strncmp(tok, "nack=", 5) == 0) {
                n_ack = atoi(tok + 5);
            } else if (strncmp(tok, "timeout=", 8) == 0) {
                timeout_us = atoi(tok + 8);
            } else if (strncmp(tok, "retry=", 6) == 0) {
                retry_num = atoi(tok + 6);
            } else {
                char fwdhostport[MAX_HOSTPORT_STRLEN];
                proto_t fwd_proto = TCP;

                addr_proto_parse(tok, fwdhostport, &fwd_proto);
                addr_parse(fwdhostport, &fwd_addr);

                if (i > 0) {
                    if (i == 1) { // morph previous FORWARD in MULTI_FORWARD
                        ccmd_last_action(ccmd)->cmd = MULTI_FORWARD;
                    }

                    fwd_type = MULTI_FORWARD;
                }

                // TODO: customize forward pkt size
                ccmd_add(ccmd, fwd_type, &val);
                ccmd_last_action(ccmd)->fwd.fwd_port = fwd_addr.sin_port;
                ccmd_last_action(ccmd)->fwd.fwd_host = fwd_addr.sin_addr.s_addr;
                
                ccmd_last_action(ccmd)->fwd.timeout = timeout_us;
                ccmd_last_action(ccmd)->fwd.retries = retry_num;
                ccmd_last_action(ccmd)->fwd.on_fail_skip = 1;
                ccmd_last_action(ccmd)->fwd.proto = fwd_proto;

                i++;
            }

            tok = strtok_r(NULL, ",", &reserve);
        }

        // TODO: allow n_ack 0 when reply messages will be optional 
        if (n_ack == 0 || (n_ack > 0 && n_ack > i)) {
            n_ack = i;
        }

        // TODO: customize forward-reply pkt size
        ccmd_node_t* reply_node = ccmd_add(ccmd, REPLY, &val);
        reply_node->resp.n_ack = n_ack;
        break; }
    case SEND_REQUEST_SIZE:
        check(pd_parse(&send_pkt_size_pd, arg), "Wrong send request size specification");
        
        check(send_pkt_size_pd.val >= MIN_SEND_SIZE, "Too small send request size, minimum is %lu", MIN_SEND_SIZE);
        check(send_pkt_size_pd.val + TCPIP_HEADERS_SIZE <= BUF_SIZE, "Too big send request size, maximum is %d", BUF_SIZE);
        break;
    case RESPONSE_SIZE: {
        //TODO: attach last -rs to original reply
        pd_spec_t val;
        check(pd_parse(&val, arg), "Wrong response size specification");
        val.min = MIN_REPLY_SIZE;
        val.max = BUF_SIZE;
        check(val.prob != FIXED || (val.val >= val.min && val.val <= val.max), "Wrong min-max range for response size");

        if (ccmd_last_reply(ccmd)) {
            ccmd_last_reply(ccmd)->pd_val = val;
        } else {
            arguments->last_resp_size = val;
        }
        break; }
    case NUM_THREADS:
        arguments->num_threads = atoi(arg);
        check(arguments->num_threads >= 1 && arguments->num_threads <= MAX_THREADS);
        break;
    case NUM_SESSIONS:
        arguments->num_sessions = atoi(arg);
        check(arguments->num_sessions >= 1);
        break;
    case CONN_RETRY_NUM:
        conn_retry_num = atoi(arg);
        check(conn_retry_num >= 1);
        break;
    case CONN_RETRY_PERIOD:
        conn_retry_period_ms = atoi(arg);
        check(conn_retry_period_ms >= 200);
        break;
    case CONN_TIMES:
        conn_times = 1;
        break;
    case CONN_NONBLOCK:
        conn_nonblock = 1;
        break;
    case PER_SESSION_OUTPUT:
        use_per_session_output = 1;
        break;
    case SCRIPT_FILENAME:
        check(script_parse(arg, state) == 0, "Wrong syntax in script %s\n", arg);
        break;
    case NO_DELAY:
        no_delay = atoi(arg);
        check(no_delay == 0 || no_delay == 1);
        break;
    case ARGP_KEY_END: // post-parsing validity checks
        addr_parse(arguments->clienthostport, &myaddr);
        addr_parse(arguments->nodehostport, &serveraddr);

        if (send_rate_pd.prob != FIXED && ramp_step_secs == 0) {
            ccmd_destroy(&ccmd);
            argp_failure(state, 1, 0, "A non-fixed rate specification needs --rate-step-secs");
        }

        if (ramp_step_secs != 0 && num_pkts == 0) {
            int num_rates = pd_len(&send_rate_pd);
            if (num_rates == -1) {
                ccmd_destroy(&ccmd);
                argp_failure(state, 1, 0, "Wrong rate specification with --num-pkts=auto");
            }
            double avg_rate = pd_avg(&send_rate_pd);
            num_pkts = avg_rate * num_rates * ramp_step_secs;
        }

        num_pkts = (num_pkts + arguments->num_sessions - 1) / arguments->num_sessions * arguments->num_sessions;
        pkts_per_session = num_pkts / arguments->num_sessions;
        if (num_pkts > MAX_PKTS || (use_per_session_output && pkts_per_session > MAX_PKTS)) {
            ccmd_destroy(&ccmd);
            argp_failure(state, 1, 0, "num_pkts: %ld > MAX_PKTS: %d, Overflow!", num_pkts, MAX_PKTS);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int script_parse(char *fname, struct argp_state *state) {
    FILE *f = fopen(fname, "r");
    check(f != NULL, "Could not open script file: %s\n", fname);
    int size = 0;
    int argc = 0;
    char **argv = NULL;

    while (!feof(f)) {
        static char line[1024];
        char *s = fgets(line, sizeof(line), f);
        if (s == NULL)
            break;
        char *tok;
        while ((tok = strsep(&s, " -\n")) != NULL) {
            if (strlen(tok) > 0) {
                // comment, ignore till end of line
                if (tok[0] == '#')
                    break;
                if (argc == size) {
                    size += 4;
                    argv = realloc(argv, sizeof(char*) * size);
                    check(argv != NULL, "realloc() failed: %s\n", strerror(errno));
                }
                argv[argc++] = strdup(tok);
            }
        }
    }
    
    for (int i=0; i<argc-1; i++) {
        // Find the option for the current input argument 
        int j = 0;
        while (argp_client_options[j].name != 0) {
            if (strncmp(argv[i], argp_client_options[j].name, strlen(argp_client_options[j].name)) == 0 || // (long) name compare 
                 (argv[i][1] == '\0' && argv[i][0] == argp_client_options[j].key)) { // short name/key compare
                argp_client_parse_opt(argp_client_options[j].key, argv[i+1], state);

                if (argp_client_options[j].arg)
                    i++;
                break;
            }
            j++;
        }
    }

    free(argv);
    return 0;
}

int main(int argc, char *argv[]) {
    static struct argp argp = { argp_client_options, argp_client_parse_opt, 0, "Distwalk Client -- the client program \
                                                                                \v NOTES: Packet sizes are in bytes and do not consider headers added on lower network levels (TCP+IP+Ethernet = 66 bytes)" };
    check(signal(SIGTERM, SIG_IGN) != SIG_ERR);
    sys_check(prctl(PR_GET_NAME, thread_name, NULL, NULL, NULL));

    ccmd_init(&ccmd);
    conn_init();
    req_init();

    struct argp_client_arguments input_args;
    argp_parse(&argp, argc, argv, ARGP_NO_HELP, 0, &input_args);
    
    // TODO: trunc pkt/resp size to BUF_SIZE when using the --exp- variants.
    // TODO: should be optional
    ccmd_attach_last_reply(ccmd, &input_args.last_resp_size);
    ccmd_last_reply(ccmd)->resp.n_ack = 1;

    if (!ccmd_last_action(ccmd)) {
        pd_spec_t val = pd_build_fixed(default_compute_us);
        ccmd_add(ccmd, COMPUTE, &val);
    }

    printf("Configuration:\n");
    printf("  clienthost=%s\n", input_args.clienthostport);
    printf("  serverhost=%s\n", input_args.nodehostport);
    printf("  num_threads: %d\n", input_args.num_threads);
    printf("  num_pkts=%lu\n", num_pkts);
    printf("  period=%sus\n", pd_str(&send_period_us_pd));
    printf("  waitspin=%d\n", use_wait_spinning);
    printf("  rate=%s\n", pd_str(&send_rate_pd));
    printf("  rate_step_secs=%d\n", ramp_step_secs);
    printf("  pkt_size=%s (+%d for headers)\n", pd_str(&send_pkt_size_pd),
           TCPIP_HEADERS_SIZE);
    printf("  resp_size=%s (+%d with headers)\n", pd_str(&ccmd_last_reply(ccmd)->pd_val),
           TCPIP_HEADERS_SIZE);
    printf("  min packet size due to header: send=%lu, reply=%lu\n",
           MIN_SEND_SIZE, MIN_REPLY_SIZE);
    printf("  max packet size: %d\n", BUF_SIZE);
    printf("  no_delay: %d\n", no_delay);
    printf("  num_sessions: %d\n", input_args.num_sessions);
    printf("  use_per_session_output: %d\n", use_per_session_output);
    printf("  num_conn_retries: %d (retry_period: %d ms)\n", conn_retry_num, conn_retry_period_ms);

    printf("  request template: ");  ccmd_log(ccmd);

    // Init random number generator
    srand(time(NULL));

    for (int i = 0; i < MAX_THREADS; i++) {
        clientSocket[i] = -1;
        if (i < input_args.num_threads) {
            check(usecs_send[i] = malloc(sizeof(usecs_send[0][0]) * MAX_PKTS));
            check(usecs_elapsed[i] = malloc(sizeof(usecs_send[0][0]) * MAX_PKTS));
        } else {
            usecs_send[i] = NULL;
            usecs_elapsed[i] = NULL;
        }
    }

    // Remember in ts_start the abs start time of the experiment
    clock_gettime(clk_id, &ts_start);

    // Run
    if (input_args.num_threads == 1) {
        thread_receiver((void*) (unsigned long) 0);
    } else {
        // Init worker threads
        for (int i = 0; i < input_args.num_threads; i++) {
            sys_check(pthread_create(&receiver[i], NULL, thread_receiver, (void *)(unsigned long) i));
        }

        for (int i = 0; i < input_args.num_threads; i++)
            pthread_join(receiver[i], NULL);

        dw_log("Joined sender and receiver threads, exiting\n");
    }

    for (int i = 0; i < input_args.num_threads; i++) {
        free(usecs_send[i]);
        free(usecs_elapsed[i]);
    }
    
    ccmd_destroy(&ccmd);
    return 0;
}

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

#define MAX_CONNS 32

#include "dw_debug.h"
#include "distrib.h"
#include "message.h"
#include "connection.h"
#include "timespec.h"
#include "ccmd.h"

__thread char thread_name[16];

int use_exp_arrivals = 0;
int use_wait_spinning = 0;

ccmd_t* ccmd = NULL; // Ordered chain of commands

// For print only
unsigned int n_store = 0;    // Number of STORE requests
unsigned int n_load = 0;     // Number of LOAD requests
unsigned int n_compute = 0;  // Number of COMPUTE requests

unsigned int default_compute_us = 1000;

pd_spec_t send_pkt_size_pd = { .prob = FIXED, .val = 1024, .std = NAN, .min = NAN, .max = NAN };
pd_spec_t send_period_us_pd = { .prob = FIXED, .val = 10000, .std = NAN, .min = NAN, .max = NAN };

unsigned long default_resp_size = 512;
int use_exp_resp_size = 0;

int no_delay = 1;
int use_per_session_output = 0;

#define MAX_THREADS 32
pthread_t sender[MAX_THREADS];
pthread_t receiver[MAX_THREADS];

#define DEFAULT_ADDR "127.0.0.1"
#define DEFAULT_PORT "7891"


// Support "host[:port]" or ":port" syntaxes
void hostport_parse_and_config(char* host_str, struct sockaddr_in* addr) {
    char* hostname = DEFAULT_ADDR;
    int port = atoi(DEFAULT_PORT);
    char* port_str;

    check(strlen(host_str) > 0,
          "Allowed host/port syntaxes are \"host[:port]\" or \":port\"");

    // Get port
    port_str = strchr(host_str, ':');
    // Now host containts hostname (or ip) only
    if (port_str) {
        dw_log("port_str: %s\n", port_str);
        *port_str = '\0';
        port_str++;

        // Convert port string to integer
        char* end_ptr = NULL;
        port = strtol(port_str, &end_ptr, 10);
        check(!*end_ptr, "Port '%s' is not a numeric value!\n", port_str);
    }

    if (strlen(host_str) > 0)
        hostname = host_str;
    dw_log("host_str: %s\n", hostname);

    // Resolve hostname
    dw_log("Resolving %s...\n", hostname);
    struct hostent *e = gethostbyname(hostname);
    check(e != NULL);
    dw_log("Host %s resolved to %d bytes: %s\n", hostname, e->h_length,
           inet_ntoa(*(struct in_addr *)e->h_addr));

    // Build Internet address
    memset((char *) addr, '\0', sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    memmove((char *) &addr->sin_addr.s_addr, (char *)e->h_addr, e->h_length);
    addr->sin_port = htons(port);

    if (port_str)
        // Restore original string (which was manipulated in-place)
        *(port_str - 1) = ':';
}

#define TCPIP_HEADERS_SIZE 66
#define MIN_SEND_SIZE (sizeof(message_t) + 2 * sizeof(command_t))
#define MIN_REPLY_SIZE sizeof(message_t)

#define MAX_PKTS 1000000
#define MAX_RATES 1000000

clockid_t clk_id = CLOCK_REALTIME;
int clientSocket[MAX_THREADS];
long usecs_send[MAX_THREADS][MAX_PKTS];
long usecs_elapsed[MAX_THREADS][MAX_PKTS];
// abs start-time of the experiment
struct timespec ts_start;

unsigned long num_pkts = 0;

unsigned int rates[MAX_RATES];
unsigned int ramp_step_secs = 0;   // if non-zero, supersedes num_pkts
unsigned int ramp_delta_rate = 0;  // added to rate every ramp_secs
unsigned int ramp_num_steps = 0;   // number of ramp-up steps
char *ramp_fname = NULL;

#define MAX_HOST_STRING 31
proto_t proto = TCP;
char serverhost[MAX_HOST_STRING] = DEFAULT_ADDR ":" DEFAULT_PORT;
char clienthost[MAX_HOST_STRING] = "0.0.0.0:0";

struct sockaddr_in serveraddr;
struct sockaddr_in myaddr;
socklen_t addr_size;

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

    sprintf(thread_name, "sndw-%d", p->thread_id);
    sys_check(prctl(PR_SET_NAME, thread_name, NULL, NULL, NULL));

    int thread_id = p->thread_id;
    int first_pkt_id = p->first_pkt_id;
    int num_send_pkts = p->num_send_pkts;
    struct timespec ts_now;

    clock_gettime(clk_id, &ts_now);
    pd_init(time(NULL));

    int rate_start = 1000000.0 / send_period_us_pd.val;

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
        assert(m->req_size <= BUF_SIZE && m->req_size >= m->num * sizeof(command_t));

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

        if (ramp_step_secs != 0 && pkt_id > 0) {
            int step =
                usecs_send[thread_id][idx(pkt_id)] / 1000000 / ramp_step_secs;
            int old_rate = 1000000.0 / send_period_us_pd.val;
            int rate;
            if (ramp_fname != NULL)
                rate = rates[(step < ramp_num_steps) ? step
                                                     : (ramp_num_steps - 1)];
            else
                rate = rate_start + step * ramp_delta_rate;
            send_period_us_pd.val = 1000000.0 / rate;
            if (old_rate != rate)
                dw_log("old_rate: %d, rate: %d\n", old_rate, rate);
        }
    }

    dw_log("Sender thread terminating\n");

    return 0;
}

void *thread_receiver(void *data) {
    int thread_id = (int)(unsigned long)data;

    sprintf(thread_name, "rcvw-%d", thread_id);
    sys_check(prctl(PR_SET_NAME, thread_name, NULL, NULL, NULL));

    unsigned char *recv_buf = malloc(BUF_SIZE);
    check(recv_buf != NULL);


    for (int i = 0; i < num_pkts; i++) {
        thread_data_t thr_data;

        if (i % pkts_per_session == 0) {
            /*---- Create the socket. The three arguments are: ----*/
            /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in
             * this case) */
            if (proto == TCP) {
                clientSocket[thread_id] = socket(PF_INET, SOCK_STREAM, 0);

                sys_check(setsockopt(clientSocket[thread_id], IPPROTO_TCP,
                                 TCP_NODELAY, (void *)&no_delay,
                                 sizeof(no_delay)));
            } else {
                clientSocket[thread_id] = socket(PF_INET, SOCK_DGRAM, 0);
            }

            dw_log("Binding to %s:%d\n", inet_ntoa(myaddr.sin_addr),
                   ntohs(myaddr.sin_port));

            /*---- Bind the address struct to the socket ----*/
            sys_check(bind(clientSocket[thread_id], (struct sockaddr *)&myaddr,
                           sizeof(myaddr)));

            /*---- Connect the socket to the server using the address struct
             * ----*/
            addr_size = sizeof(serveraddr);

            dw_log("Connecting to %s:%d (i=%d) ...\n", inet_ntoa((struct in_addr) {serveraddr.sin_addr.s_addr}), ntohs(serveraddr.sin_port), i);
            sys_check(connect(clientSocket[thread_id],
                              (struct sockaddr *)&serveraddr, addr_size));

            /* spawn sender once connection is established */

            int conn_id = conn_alloc(clientSocket[thread_id], serveraddr, proto);
            conn_set_status_by_id(conn_id, READY);

            // TODO (?) thr_data is allocated in the stack and reused for every thread, possible (but completly improbable) race condition
            thr_data.thread_id = thread_id;
            thr_data.conn_id = conn_id;
            thr_data.first_pkt_id = i,
            thr_data.num_send_pkts = pkts_per_session;
            assert(pthread_create(&sender[thread_id], NULL, thread_sender,
                                  (void *)&thr_data) == 0);
        }

        /*---- Read the message from the server into the buffer ----*/
        // TODO: support receive of variable reply-size requests
        conn_info_t *conn = conn_get_by_id(thr_data.conn_id);
        message_t *m = NULL;
        int recv;

        do {
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

        struct timespec ts_now;
        clock_gettime(clk_id, &ts_now);
        unsigned long usecs = (ts_now.tv_sec - ts_start.tv_sec) * 1000000 +
                              (ts_now.tv_nsec - ts_start.tv_nsec) / 1000;
        usecs_elapsed[thread_id][idx(pkt_id)] =
            usecs - usecs_send[thread_id][idx(pkt_id)];
        dw_log("req_id %u elapsed %ld us\n", pkt_id,
               usecs_elapsed[thread_id][idx(pkt_id)]);

    skip:
        if ((i + 1) % pkts_per_session == 0) {
            dw_log(
                "Session is over (after receive of pkt %d), closing socket\n",
                i);
            close(clientSocket[thread_id]);
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
                memset(&usecs_send[thread_id][0], 0, sizeof(usecs_send[thread_id]));
                memset(&usecs_elapsed[thread_id][0], 0, sizeof(usecs_elapsed[thread_id]));
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
    SKIP_CMD = 's',
    FORWARD_CMD = 'F',
    SCRIPT_FILENAME = 'f',

    BIND_CLIENT = 0x200,
    EXPON_ARRIVAL,
    WAIT_SPIN,
    RAMP_STEP_SECS,
    RAMP_DELTA_RATE,
    RAMP_NUM_STEPS,
    RATE_FILENAME,
    SEND_REQUEST_SIZE,
    EXPON_SEND_REQUEST_SIZE,
    RESPONSE_SIZE,
    EXPON_RESPONSE_SIZE,
    NO_DELAY,
    NUM_THREADS,
    NUM_SESSIONS,
    PER_SESSION_OUTPUT,
    TCP_OPT_ARG,
    UDP_OPT_ARG,
    EXPON_COMP_TIME,
};

struct argp_client_arguments {
    int use_exp_arrivals;
    int num_sessions;
    int num_threads;
    pd_spec_t last_resp_size;
};

static struct argp_option argp_client_options[] = {
    // long name, short name, value name, flag, description
    { "cl",                 BIND_CLIENT,            "host[:port]|:port",   0, "Set client bindname and bindport"},
    { "tcp",                TCP_OPT_ARG,            "host[:port]",         0, "Use TCP communication protocol with the (initial) distwalk node"},
    { "udp",                UDP_OPT_ARG,            "host[:port]",         0, "Use UDP communication protocol with the (initial) distwalk node"},
    { "num-pkts",           NUM_PKTS,               "n",                   0, "Number of packets sent by each thread (across all sessions"},
    { "period",             PERIOD,                 "n",                   0, "Inter-send period for each thread (average, if -ea is specified) (in usec)"},
    { "rate",               RATE,                   "n",                   0, "Packet sending rate (average, -ea is specified) (in pkts per sec)"},
    { "exp-arrivals",       EXPON_ARRIVAL,           0,                    0, "Set exponentially distributed inter-send times for each thread [currently not implemented]"},
    { "ea",                 EXPON_ARRIVAL,           0,  OPTION_ALIAS },
    { "wait-spin",          WAIT_SPIN,               0,                    0, "Spin-wait instead of sleeping till next sending time"},
    { "ws",                 WAIT_SPIN,               0,  OPTION_ALIAS },
    { "ramp-num-steps",     RAMP_NUM_STEPS,         "n",                   0, "Number of rate-steps"},
    { "rns",                RAMP_NUM_STEPS,         "n", OPTION_ALIAS},
    { "ramp-step-secs",     RAMP_STEP_SECS,         "n",                   0, "Duration of each rate-step (in sec)"},
    { "rss",                RAMP_STEP_SECS,         "n", OPTION_ALIAS},
    { "ramp-delta-rate",    RAMP_DELTA_RATE,        "n",                   0, "Rate increment at each rate-step"},
    { "rdr",                RAMP_DELTA_RATE,        "n", OPTION_ALIAS},
    { "rate-filename",      RATE_FILENAME,          "path/to/file.dat",    0, "Load rates from a specified file"},
    { "rfn",                RATE_FILENAME,          "path/to/file.dat", OPTION_ALIAS},
    { "comp-time",          COMP_TIME,              "n",                   0, "Per-request processing time (distribution, or usec)"},
    { "exp-comp",           EXPON_COMP_TIME,         0,                    0, "Exponentially distributed per-request processing times [currently not implemented]"},
    { "ec",                 EXPON_COMP_TIME,         0, OPTION_ALIAS},
    { "store-data",         STORE_DATA,             "n",                   0, "Per-store data payload size (in bytes)"},
    { "load-data",          LOAD_DATA,              "n",                   0, "Per-load data payload size (in bytes)"},
    { "skip",               SKIP_CMD,               "n[,prob=val]",        0, "Skip (with given probability) the next n commands"},
    { "forward",            FORWARD_CMD, "ip:port[,ip:port,...][,nack=N]", 0, "Send a number of FORWARD message to the ip:port list, wait for N replies"},
    { "snd-pkt-size",       SEND_REQUEST_SIZE,      "n",                   0, "Set payload size of sent requests (average, if -eps is specified) (in bytes)"},
    { "ps",                 SEND_REQUEST_SIZE,      "n", OPTION_ALIAS},
    { "exp-snd-pkt-size",   EXPON_SEND_REQUEST_SIZE, 0,                    0, "Exponentially distributed payload size of sent requests" },
    { "eps",                EXPON_SEND_REQUEST_SIZE, 0, OPTION_ALIAS},
    { "resp-pkt-size",      RESPONSE_SIZE,          "n",                   0, "Set payload size of received responses (average, if -ers is specified) (in bytes)"},
    { "rs",                 RESPONSE_SIZE,          "n", OPTION_ALIAS},
    { "exp-resp-pkt-size",  EXPON_RESPONSE_SIZE,     0,                    0, "Exponentially distributed payload size of received responses [currently not implemented]"},
    { "ers",                EXPON_RESPONSE_SIZE,     0,  OPTION_ALIAS},
    { "num-threads",        NUM_THREADS,            "N",                   0, "Number of threads dedicated to communication" },
    { "nt",                 NUM_THREADS,            "N", OPTION_ALIAS },
    { "num-sessions",       NUM_SESSIONS,           "N",                   0, "Number of sessions each thread establishes with the (initial) distwalk node"},
    { "ns",                 NUM_SESSIONS,           "N", OPTION_ALIAS},      
    { "no-delay",           NO_DELAY,             "0|1",                   0, "Set value of TCP_NODELAY socket option"},
    { "nd",                 NO_DELAY,             "0|1", OPTION_ALIAS },
    { "per-session-output", PER_SESSION_OUTPUT,       0,                   0, "Output response times at end of each session (implies some delay between sessions but saves memory)" },
    { "pso",                PER_SESSION_OUTPUT,       0, OPTION_ALIAS },
    { "script-filename",    SCRIPT_FILENAME,        "path/to/file",        0, "Continue reading commands from script file (can be intermixed with regular options)"},
    { "help",               HELP,                    0,                    0, "Show this help message", 1 },
    { "usage",              USAGE,                   0,                    0, "Show a short usage message", 1 },
    { 0 }
};

static error_t argp_client_parse_opt(int key, char *arg, struct argp_state *state) {
        /* Get the input argument from argp_parse, which we
        know is a pointer to our arguments structure. */
    struct argp_client_arguments *arguments = state->input;

    switch(key) {
    case HELP:
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
        break;
    case USAGE:
        argp_state_help(state, state->out_stream, ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK);
        break;
    case BIND_CLIENT:
        strncpy(clienthost, arg, MAX_HOST_STRING-1);
        clienthost[MAX_HOST_STRING-1] = '\0';
        break;
    case TCP_OPT_ARG:
        strncpy(serverhost, arg, MAX_HOST_STRING-1);
        serverhost[MAX_HOST_STRING-1] = '\0';
        proto = TCP;
        break;
    case UDP_OPT_ARG:
        strncpy(serverhost, arg, MAX_HOST_STRING-1);
        serverhost[MAX_HOST_STRING-1] = '\0';
        proto = UDP;
        break;
    case NUM_PKTS:
        num_pkts = atoi(arg);
        break;
    case PERIOD:
        assert(pd_parse(&send_period_us_pd, arg));
        break;
    case RATE:
        send_period_us_pd = pd_build_fixed(1000000.0 / atof(arg));
        break;
    case EXPON_ARRIVAL:
        use_exp_arrivals = 1;
        break;
    case WAIT_SPIN:
        use_wait_spinning = 1;
        break;
    case RAMP_NUM_STEPS:
        ramp_num_steps = atoi(arg);
        break;
    case RAMP_STEP_SECS:
        ramp_step_secs = atoi(arg);
        break;
    case RAMP_DELTA_RATE:
        ramp_delta_rate = atoi(arg);
        break;
    case RATE_FILENAME:
        ramp_fname = arg;
        break;
    case COMP_TIME: {
        pd_spec_t val;
        assert(pd_parse(&val, arg));
        ccmd_add(ccmd, COMPUTE, &val);

        n_compute++;
        break; }
    case STORE_DATA: {
        pd_spec_t val;
        assert(pd_parse(&val, arg));
        ccmd_add(ccmd, STORE, &val);

        n_store++;
        break; }
    case LOAD_DATA: {
        pd_spec_t val;
        assert(pd_parse(&val, arg));
        ccmd_add(ccmd, LOAD, &val);

        n_load++; 
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

        n_load++; // @TODO What's the purpose of this?
        break; }
    case FORWARD_CMD: {
        struct sockaddr_in addr;
        command_type_t fwd_type = FORWARD;
        pd_spec_t val = pd_build_fixed(default_resp_size);

        char *tok;
        int n_ack = 0;
        int i = 0;
        
        while ((tok = strsep(&arg, ",")) != NULL) {
            if (sscanf(tok, "nack=%d", &n_ack) == 1)
                continue;
            
            hostport_parse_and_config(tok, &addr);

            if (arg) {
                fwd_type = MULTI_FORWARD;
            }

            // TODO: customize forward pkt size
            ccmd_add(ccmd, fwd_type, &val);
            ccmd_last_action(ccmd)->fwd.fwd_port = addr.sin_port;
            ccmd_last_action(ccmd)->fwd.fwd_host = addr.sin_addr.s_addr;
            // TODO: customize forward timeout and opts
            ccmd_last_action(ccmd)->fwd.timeout = 0;
            ccmd_last_action(ccmd)->fwd.retries = 0;
            ccmd_last_action(ccmd)->fwd.on_fail_skip = 0;
            ccmd_last_action(ccmd)->fwd.proto = TCP;


            i++;
        }

        // TODO: allow n_ack 0 ???
        if (n_ack == 0 || (n_ack > 0 && n_ack > i)) {
            n_ack = i;
        }

        // TODO: customize forward-reply pkt size
        ccmd_add(ccmd, REPLY, &val);
        ccmd_last_reply(ccmd)->resp.n_ack = n_ack;
        break; }
    case SEND_REQUEST_SIZE:
        assert(pd_parse(&send_pkt_size_pd, arg));
        
        assert(send_pkt_size_pd.val >= MIN_SEND_SIZE);
        assert(send_pkt_size_pd.val + TCPIP_HEADERS_SIZE <= BUF_SIZE);
        break;
    case EXPON_SEND_REQUEST_SIZE:
        send_pkt_size_pd.prob = EXPON;
        break;
    case RESPONSE_SIZE: {
        //TODO: attach last -rs to original reply
        pd_spec_t val;
        assert(pd_parse(&val, arg));
        val.min = MIN_REPLY_SIZE;
        val.max = BUF_SIZE;
        check(val.prob != FIXED || (val.val >= val.min && val.val <= val.max));

        if (ccmd_last_reply(ccmd)) {
            ccmd_last_reply(ccmd)->pd_val = val;
        } else {
            arguments->last_resp_size = val;
        }
        break; }
    case EXPON_RESPONSE_SIZE:
        use_exp_resp_size = 1;
        break;
    case NUM_THREADS:
        arguments->num_threads = atoi(arg);
        break;
    case NUM_SESSIONS:
        arguments->num_sessions = atoi(arg);
        check(arguments->num_sessions >= 1);
        break;
    case PER_SESSION_OUTPUT:
        use_per_session_output = 1;
        break;
    case SCRIPT_FILENAME:
        check(script_parse(arg, state) == 0, "Wrong syntax in script %s\n", arg);
        break;
    case NO_DELAY:
        no_delay = atoi(arg);
        assert(no_delay == 0 || no_delay == 1);
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
    struct argp_client_arguments input_args;
    input_args.num_sessions = 1;
    input_args.num_threads = 1;
    input_args.last_resp_size = pd_build_fixed(default_resp_size);

    check(signal(SIGTERM, SIG_IGN) != SIG_ERR);

    sys_check(prctl(PR_GET_NAME, thread_name, NULL, NULL, NULL));

    ccmd_init(&ccmd);
    conn_init();
    req_init();

    argp_parse(&argp, argc, argv, ARGP_NO_HELP, 0, &input_args);
    
    // TODO: trunc pkt/resp size to BUF_SIZE when using the --exp- variants.
    // TODO: should be optional
    ccmd_attach_last_reply(ccmd, &input_args.last_resp_size);
    ccmd_last_reply(ccmd)->resp.n_ack = 1;

    if (n_compute + n_store + n_load > 0 && num_pkts <= 0) {
        num_pkts = 1;
    }

    if (n_compute + n_load + n_store <= 0) {
        if (num_pkts <= 0) {
            num_pkts = 1;
        }

        pd_spec_t val = pd_build_fixed(default_compute_us);
        ccmd_add(ccmd, COMPUTE, &val);

        n_compute++;
    }

    if (ramp_step_secs != 0) {
        if (ramp_fname != NULL) {
            check(ramp_delta_rate == 0);
            FILE *ramp_fid = fopen(ramp_fname, "r");
            check(ramp_fid != NULL);
            int cnt = 0;
            for (ramp_num_steps = 0; !feof(ramp_fid);) {
                unsigned int r;
                int read_fields = fscanf(ramp_fid, "%u", &r);
                if (read_fields == 1) {
                    check(ramp_num_steps < MAX_RATES);
                    rates[ramp_num_steps] = r;
                    cnt += r * ramp_step_secs;
                    ramp_num_steps++;
                }
            }
            fclose(ramp_fid);
            send_period_us_pd.val = 1000000.0 / rates[0];
            if (num_pkts == 0 || num_pkts > cnt) num_pkts = cnt;
        } else {
            num_pkts = 0;
            int r = send_period_us_pd.val;
            for (int s = 0; s < ramp_num_steps; s++) {
                num_pkts += r * ramp_step_secs;
                r += ramp_delta_rate;
            }
        }
    }

    hostport_parse_and_config(serverhost, &serveraddr);
    hostport_parse_and_config(clienthost, &myaddr);

    /* Set all bits of the padding field to 0 */
    memset(myaddr.sin_zero, '\0', sizeof(myaddr.sin_zero));

    num_pkts = (num_pkts + input_args.num_sessions - 1) / input_args.num_sessions * input_args.num_sessions;
    pkts_per_session = num_pkts / input_args.num_sessions;

    assert(num_pkts <= MAX_PKTS ||
           (use_per_session_output && pkts_per_session <= MAX_PKTS));

    printf("Configuration:\n");
    printf("  clienthost=%s\n", clienthost);
    printf("  serverhost=%s\n", serverhost);
    printf("  num_threads: %d\n", input_args.num_threads);
    printf("  num_pkts=%lu (COMPUTE:%d, STORE:%d, LOAD:%d)\n", num_pkts,
           n_compute, n_store, n_load);
    printf("  rate=%g, exp_arrivals=%d\n", 1000000.0 / send_period_us_pd.val, use_exp_arrivals);
    printf("  period=%sus\n", pd_str(&send_period_us_pd));
    printf("  waitspin=%d\n", use_wait_spinning);
    printf("  ramp_num_steps=%d, ramp_delta_rate=%d, ramp_step_secs=%d\n",
           ramp_num_steps, ramp_delta_rate, ramp_step_secs);
    printf("  pkt_size=%s (+%d for headers)\n", pd_str(&send_pkt_size_pd),
           TCPIP_HEADERS_SIZE);
    /*printf("  resp_size=%lu (%lu with headers), use_exp_resp_size=%d\n", resp_size,
           resp_size + TCPIP_HEADERS_SIZE, use_exp_resp_size); TODO: Update */
    printf("  min packet size due to header: send=%lu, reply=%lu\n",
           MIN_SEND_SIZE, MIN_REPLY_SIZE);
    printf("  max packet size: %d\n", BUF_SIZE);
    printf("  no_delay: %d\n", no_delay);
    printf("  num_sessions: %d\n", input_args.num_sessions);
    printf("  use_per_session_output: %d\n", use_per_session_output);

    printf("  request template: ");  ccmd_log(ccmd);

    // Init random number generator
    srand(time(NULL));



    for (int i = 0; i < MAX_THREADS; i++) clientSocket[i] = -1;

    // Remember in ts_start the abs start time of the experiment
    clock_gettime(clk_id, &ts_start);

    for (int i = 0; i < input_args.num_threads; i++)
        assert(pthread_create(&receiver[i], NULL, thread_receiver,
                              (void *)(unsigned long)i) == 0);

    for (int i = 0; i < input_args.num_threads; i++) pthread_join(receiver[i], NULL);

    dw_log("Joined sender and receiver threads, exiting\n");

    return 0;
}

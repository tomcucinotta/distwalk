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

#include "cw_debug.h"
#include "expon.h"
#include "message.h"
#include "timespec.h"
#include "ccmd.h"

int exp_arrivals = 0;
int wait_spinning = 0;

ccmd_t* ccmd = NULL; // Ordered chain of commands
command_t template_cmds[255];
int ncmd = 0;

unsigned int n_store = 0;  // Number of STORE requests
unsigned long store_nbytes = 10;  // Number of bytes to be written to the server's storage

unsigned int n_load = 0;  // Number of LOAD requests
unsigned long load_nbytes = 10;  // Number of bytes to be read from the server's storage

unsigned int n_compute = 0;        // Number of COMPUTE requests
unsigned long comptimes_us = 100;  // defaults to 100us
int exp_comptimes = 0;

unsigned long pkt_size = 128;
int exp_pkt_size = 0;

unsigned long resp_size = 128;
int exp_resp_size = 0;

int no_delay = 1;
int per_session_output = 0;

#define MAX_THREADS 32
pthread_t sender[MAX_THREADS];
pthread_t receiver[MAX_THREADS];

void safe_send(int sock, unsigned char *buf, size_t len) {
    while (len > 0) {
        int sent;
        sys_check(sent = send(sock, buf, len, 0));
        cw_log("Sent %d bytes.\n", sent);
        buf += sent;
        len -= sent;
    }
}

// returns 1 if all bytes sent correctly, 0 if errors occurred
int send_all(int sock, unsigned char *buf, size_t len) {
    while (len > 0) {
        int sent;
        sent = send(sock, buf, len, 0);
        if (sent < 0) {
            fprintf(stderr, "send() failed: %s\n", strerror(errno));
            return 0;
        }
        buf += sent;
        len -= sent;
    }
    return 1;
}

size_t safe_recv(int sock, unsigned char *buf, size_t len) {
    size_t read_tot = 0;
    while (len > 0) {
        int read;
        sys_check(read = recv(sock, buf, len, 0));
        cw_log("Read %d bytes\n", read);
        if (read == 0) break;
        buf += read;
        len -= read;
        read_tot += read;
    }
    return read_tot;
}

// return len, or -1 if an error occurred on read()
size_t recv_all(int sock, unsigned char *buf, size_t len) {
    size_t read_tot = 0;
    while (len > 0) {
        int read;
        read = recv(sock, buf, len, 0);
        if (read < 0) {
            perror("recv() failed: ");
            return -1;
        } else if (read == 0)
            return read_tot;
        buf += read;
        len -= read;
        read_tot += read;
    }
    return read_tot;
}

// Weighted probabilities of executing a COMPUTE/STORE/LOAD request
//(Used for randomly patterned messages)
int sum_w = 0;
int weights[3] = {0, 0, 0};  // 0 compute, 1 store, 2 load


void host_net_config(char* host_str, struct sockaddr_in* addr) {
    char* hostname;
    char* port_str;
    int port;

    // Parse host:port string
    hostname = host_str;

    // Get port
    port_str = strchr(host_str, ':');
    if (!port_str) {
        fprintf(stderr, "Missing ':' in <host>:<port>!\n");
        exit(EXIT_FAILURE);
    }

    // Now host containts hostname (or ip) only
    *port_str = '\0';
    port_str++;

    // Convert port string in integer
    char* end_ptr = NULL;
    port = strtol(port_str, &end_ptr, 10);
    if (*end_ptr) {
        fprintf(stderr, "Port '%s' is not a numeric value!\n", port_str);
        exit(EXIT_FAILURE);
    }

    // Hostname Resolve
    cw_log("Resolving %s...\n", hostname);
    struct hostent *e = gethostbyname(hostname);
    check(e != NULL);
    cw_log("Host %s resolved to %d bytes: %s\n", hostname, e->h_length,
           inet_ntoa(*(struct in_addr *)e->h_addr));

    // Build Internet address
    bzero((char *) addr, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    bcopy((char *)e->h_addr, (char *) &addr->sin_addr.s_addr, e->h_length);
    addr->sin_port = htons(port);

    // Restore original string (which was manipulated in-place)
    *(port_str - 1) = ':';
}

//TODO: Deprecated with recent client interface update
// Weighted command type picker
command_type_t pick_next_cmd() {
    int r = rand() % sum_w;
    int i = 0;

    while (r >= weights[i] && i < 3) {
        r -= weights[i];
        i++;
    }

    return (command_type_t)i;
}

#define TCPIP_HEADERS_SIZE 66
#define MIN_SEND_SIZE (sizeof(message_t) + 2 * sizeof(command_t))
#define MIN_REPLY_SIZE sizeof(message_t)

uint32_t exp_packet_size(uint32_t avg, uint32_t min, uint32_t max,
                         struct drand48_data *rnd_buf) {
    /* The pkt_size in input does not consider header size but I need to take
     * that into account if I want to generate an exponential distribution.
     */
    uint32_t ret = lround(expon(1.0 / (avg + TCPIP_HEADERS_SIZE), rnd_buf));

    if (ret >= TCPIP_HEADERS_SIZE)
        ret -= TCPIP_HEADERS_SIZE;
    else
        ret = 0;

    if (ret < min)
        return min;
    else if (ret > max)
        return max;
    else
        return ret;
}

#define MAX_PKTS 1000000
#define MAX_RATES 1000000

clockid_t clk_id = CLOCK_REALTIME;
int clientSocket[MAX_THREADS];
long usecs_send[MAX_THREADS][MAX_PKTS];
long usecs_elapsed[MAX_THREADS][MAX_PKTS];
// abs start-time of the experiment
struct timespec ts_start;
unsigned int rate = 1000;  // pkt/s rate (period is its inverse)

unsigned long num_pkts = 0;

unsigned int rates[MAX_RATES];
unsigned int ramp_step_secs = 0;   // if non-zero, supersedes num_pkts
unsigned int ramp_delta_rate = 0;  // added to rate every ramp_secs
unsigned int ramp_num_steps = 0;   // number of ramp-up steps
char *ramp_fname = NULL;

#define MAX_HOST_STRING 31
char serverhost[MAX_HOST_STRING] = "127.0.0.1:7891";
char clienthost[MAX_HOST_STRING] = "0.0.0.0:0";

struct sockaddr_in serveraddr;
struct sockaddr_in myaddr;
socklen_t addr_size;

int num_threads = 1;
int num_sessions = 1;

unsigned long pkts_per_session;

typedef struct {
    int thread_id;
    int first_pkt_id;
    int num_send_pkts;
} thread_data_t;

unsigned long curr_period_us() { return 1000000 / rate; }

int idx(int pkt_id) {
    int val = per_session_output ? pkt_id % pkts_per_session : pkt_id;
    assert(val < MAX_PKTS);
    return val;
}

void *thread_sender(void *data) {
    thread_data_t *p = (thread_data_t *)data;
    int thread_id = p->thread_id;
    int first_pkt_id = p->first_pkt_id;
    int num_send_pkts = p->num_send_pkts;
    unsigned char *send_buf = malloc(BUF_SIZE);
    check(send_buf != NULL);
    struct timespec ts_now;
    struct drand48_data rnd_buf;

    clock_gettime(clk_id, &ts_now);
    srand48_r(time(NULL), &rnd_buf);

    int rate_start = rate;

    message_t *m = (message_t *)send_buf;

    if (exp_pkt_size) {
        m->req_size =
            exp_packet_size(pkt_size, MIN_SEND_SIZE, BUF_SIZE, &rnd_buf);
    } else {
        m->req_size = pkt_size;
    }

    ccmd_dump(ccmd, m);

    for (int i = 0; i < num_send_pkts; i++) {
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

        //TODO: Change this
        if (m->cmds[0].cmd == COMPUTE) {
            if (exp_comptimes) {
                m->cmds[0].u.comp_time_us =
                    lround(expon(1.0 / comptimes_us, &rnd_buf));
            } else {
                m->cmds[0].u.comp_time_us = comptimes_us;
            }
        }


        //TODO: Do something similar for every reply
        // Last REPLY resp_size
        if (exp_resp_size) {
            m->cmds[m->num-1].u.fwd.pkt_size =
                exp_packet_size(resp_size, MIN_REPLY_SIZE, BUF_SIZE, &rnd_buf);
        } else {
            assert(resp_size <= BUF_SIZE);
            m->cmds[m->num-1].u.fwd.pkt_size = resp_size;
        }


        // TODO: Compute the return bytes properly
        uint32_t return_bytes = m->cmds[m->num-1].u.fwd.pkt_size;
        for (int i=0; i<m->num; i++) {
            if (m->cmds[i].cmd == LOAD) {
                return_bytes += load_nbytes;
            }
        }
        

        // Prints
        for(int i=0; i<m->num; i++){
            if (i < m->num-1) {
                printf("%s->", get_command_name(m->cmds[i].cmd));
            }
            else {
                printf("%s", get_command_name(m->cmds[i].cmd));
            }
        }

        cw_log(":sending %u bytes (will expect %u bytes in response)...\n",
               m->req_size, return_bytes);
        assert(m->req_size <= BUF_SIZE);
        if (!send_all(clientSocket[thread_id], send_buf, m->req_size)) {
            fprintf(stderr,
                    "Forcing premature termination of sender thread while "
                    "attempting to send pkt %d\n",
                    pkt_id);
            break;
        }

        unsigned long period_us = curr_period_us();
        unsigned long period_ns;
        if (exp_arrivals) {
            period_ns = lround(expon(1.0 / period_us, &rnd_buf) * 1000.0);
        } else {
            period_ns = period_us * 1000;
        }
        struct timespec ts_delta =
            (struct timespec){period_ns / 1000000000, period_ns % 1000000000};

        ts_now = ts_add(ts_now, ts_delta);

        if (wait_spinning) {
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
            int old_rate = rate;
            if (ramp_fname != NULL)
                rate = rates[(step < ramp_num_steps) ? step
                                                     : (ramp_num_steps - 1)];
            else
                rate = rate_start + step * ramp_delta_rate;
            if (old_rate != rate)
                cw_log("old_rate: %d, rate: %d\n", old_rate, rate);
        }
    }

    cw_log("Sender thread terminating\n");

    return 0;
}

void *thread_receiver(void *data) {
    int thread_id = (int)(unsigned long)data;
    unsigned char *recv_buf = malloc(BUF_SIZE);
    check(recv_buf != NULL);

    for (int i = 0; i < num_pkts; i++) {
        if (i % pkts_per_session == 0) {
            /*---- Create the socket. The three arguments are: ----*/
            /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in
             * this case) */
            clientSocket[thread_id] = socket(PF_INET, SOCK_STREAM, 0);

            sys_check(setsockopt(clientSocket[thread_id], IPPROTO_TCP,
                                 TCP_NODELAY, (void *)&no_delay,
                                 sizeof(no_delay)));

            cw_log("Binding to %s:%d\n", inet_ntoa(myaddr.sin_addr),
                   myaddr.sin_port);

            /*---- Bind the address struct to the socket ----*/
            sys_check(bind(clientSocket[thread_id], (struct sockaddr *)&myaddr,
                           sizeof(myaddr)));

            /*---- Connect the socket to the server using the address struct
             * ----*/
            addr_size = sizeof(serveraddr);

            cw_log("Connecting to %s:%d (i=%d) ...\n", inet_ntoa((struct in_addr) {serveraddr.sin_addr.s_addr}), ntohs(serveraddr.sin_port), i);
            sys_check(connect(clientSocket[thread_id],
                              (struct sockaddr *)&serveraddr, addr_size));

            /* spawn sender once connection is established */
            thread_data_t thr_data = {.thread_id = thread_id,
                                      .first_pkt_id = i,
                                      .num_send_pkts = pkts_per_session};
            assert(pthread_create(&sender[thread_id], NULL, thread_sender,
                                  (void *)&thr_data) == 0);
        }

        /*---- Read the message from the server into the buffer ----*/
        // TODO: support receive of variable reply-size requests
        cw_log("Receiving %lu bytes (header)\n", sizeof(message_t));
        unsigned long read =
            recv_all(clientSocket[thread_id], recv_buf, sizeof(message_t));
        if (read != sizeof(message_t)) {
            printf(
                "Error: read %lu bytes while expecting %lu! Forcing premature "
                "end of session!\n",
                read, sizeof(message_t));
            unsigned long skip_pkts =
                pkts_per_session - ((i + 1) % pkts_per_session);
            printf("Fast-forwarding i by %lu pkts\n", skip_pkts);
            i += skip_pkts;
            goto skip;
        }
        message_t *m = (message_t *)recv_buf;
        unsigned long pkt_id = m->req_id;
        cw_log("Received %lu bytes, req_id=%lu, pkt_size=%u, ops=%d\n", read,
               pkt_id, m->req_size, m->num);
        cw_log("Expecting further %lu bytes (total pkt_size %u bytes)\n",
               m->req_size - read, m->req_size);
        assert(m->req_size >= sizeof(message_t));
        unsigned long read2 = recv_all(clientSocket[thread_id], recv_buf + read,
                                       m->req_size - read);
        if (read2 != m->req_size - read) {
            printf(
                "Error: read %lu bytes while expecting %lu! Forcing premature "
                "end of session!\n",
                read2, m->req_size - read);
            unsigned long skip_pkts =
                pkts_per_session - ((i + 1) % pkts_per_session);
            printf("Fast-forwarding i by %lu pkts\n", skip_pkts);
            i += skip_pkts;
            goto skip;
        }

        struct timespec ts_now;
        clock_gettime(clk_id, &ts_now);
        unsigned long usecs = (ts_now.tv_sec - ts_start.tv_sec) * 1000000 +
                              (ts_now.tv_nsec - ts_start.tv_nsec) / 1000;
        usecs_elapsed[thread_id][idx(pkt_id)] =
            usecs - usecs_send[thread_id][idx(pkt_id)];
        cw_log("req_id %lu elapsed %ld us\n", pkt_id,
               usecs_elapsed[thread_id][idx(pkt_id)]);

    skip:
        if ((i + 1) % pkts_per_session == 0) {
            cw_log(
                "Session is over (after receive of pkt %d), closing socket\n",
                i);
            close(clientSocket[thread_id]);
            if (per_session_output) {
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
                bzero(&usecs_send[thread_id][0], sizeof(usecs_send[thread_id]));
                bzero(&usecs_elapsed[thread_id][0],
                      sizeof(usecs_elapsed[thread_id]));
            }
            cw_log("Joining sender thread\n");
            pthread_join(sender[thread_id], NULL);
        }
    }

    if (!per_session_output) {
        for (int i = 0; i < num_pkts; i++) {
            int sess_id = i / pkts_per_session;
            printf(
                "t: %ld us, elapsed: %ld us, req_id: %d, thr_id: %d, sess_id: "
                "%d\n",
                usecs_send[thread_id][i], usecs_elapsed[thread_id][idx(i)], i,
                thread_id, sess_id);
        }
    }

    cw_log("Receiver thread terminating\n");
    return 0;
}

int main(int argc, char *argv[]) {
    check(signal(SIGTERM, SIG_IGN) != SIG_ERR);

    ccmd_init(&ccmd);

    uint32_t return_bytes = resp_size;

    argc--;
    argv++;
    while (argc > 0) {
        //TODO: Remove all weight parameters, as they do not work with the new
        //client interface
        if (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0) {
            printf(
                "Usage: dw_client [-h|--help] [-cl hostname:port] "
                "[-sv hostname:port] [-n num_pkts] [-p period(us)] "
                "[-r|--rate rate] [-ea|--exp-arrivals] [-ws|--wait-spin] "
                "[-rss|--ramp-step-secs secs] [-rdr|--ramp-delta-rate r] "
                "[-rns|--ramp-num-steps n] [-rfn|--rate-file-name "
                "rates_file.dat] [-C|--comp-time comp_time(us)] "
                "[-ec|--exp-comp] [-S|--store-data n(bytes)] [-L|--load-data "
                "n(bytes)] [-Cw|--comp-weight w] [-Sw|--store-weight w] "
                "[-Lw|--load-weight w] [-ps req_size] [-eps|--exp-req-size] "
                "[-rs resp_size] [-ers|--exp-resp-size] [-nd|--no-delay val] "
                "[-nt|--num-threads threads] [-ns|--num-sessions] "
                "[-pso|--per-session-output]\n"
                "\n"
                "Options:\n"
                "  -h|--help ....................... This help message\n"
                "  -sv hostname:port ............... Set Server host\n"
                "  -cl hostname:port ............... Set Client host\n"
                "  -n num_pkts ..................... Set number of packets "
                "sent by each thread (across all sessions)\n"
                "  -p period(us) ................... Set inter-send period for "
                "each thread (average, if -ea is specified)\n"
                "  -r rate ......................... Set sending rate for each "
                "rate (average, if -ea is specified)\n"
                "  -ws|--wait-spin ................. Spin-wait instead of "
                "sleeping till next sending time\n"
                "  -ea|--exp-arrivals .............. Set exponentially "
                "distributed inter-send times for each thread\n"
                "  -rss|--ramp-step-secs secs ...... Set duration of each "
                "rate-step\n"
                "  -rdr|--ramp-delta-rate rate ..... Set rate increment at each "
                "rate-step\n"
                "  -rns|--ramp-num-steps n ......... Set number of rate-steps\n"
                "  -rfn|--rate-file-name fname ..... Load rates from specified "
                "file\n"
                "  -C|--comp-time time(us) ......... Set per-request "
                "processing time (average, if -ec is specified)\n"
                "  -ec|--exp-comp .................. Set exponentially "
                "distributed per-request processing times\n"
                "  -S|--store-data bytes ........... Set per-store data size\n"
                "  -L|--load-data bytes ............ Set per-load data size\n"
                "  -F|--forward hostname:port ...... FORWARD message \n"
                "  -Cw|--comp-weight w ............. Set weight of COMPUTE in "
                "weighted random choice of operation\n"
                "  -Sw|--store-weight w ............ Set weight of STORE in "
                "weighted random choice of operation\n"
                "  -Lw|--load-weight w ............. Set weight of LOAD in "
                "weighted random choice of operation\n"
                "  -ps bytes ....................... Set size of sent requests "
                "(average, if -eps is specified)\n"
                "  -eps|--exp-req-size ............. Set exponentially "
                "distributed size of sent requests\n"
                "  -rs bytes ....................... Set size of received "
                "responses (average, if -ers is specified)\n"
                "  -ers|--exp-resp-size ............ Set exponentially "
                "distributed size of received responses\n"
                "  -nd|--no-delay [0|1] ............ Set value of TCP_NO_DELAY "
                "socket option\n"
                "  -nt|--num-threads threads ....... Set number of threads\n"
                "  -ns|--num-sessions .............. Set number of sessions "
                "each thread establishes with the server\n"
                "  -pso|--per-session-output ....... Output response times at "
                "end of each session (implies some delay between sessions but "
                "saves memory)\n"
                "\n"
                "  Notes:\n"
                "    Packet sizes are in bytes and do not consider headers "
                "added on lower network levels (TCP+IP+Ethernet = 66 bytes)\n");
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[0], "-sv") == 0) {
            assert(argc >= 2);
            strncpy(serverhost, argv[1], MAX_HOST_STRING-1);
            serverhost[MAX_HOST_STRING-1] = '\0';
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-cl") == 0) {
            assert(argc >= 2);
            strncpy(clienthost, argv[1], MAX_HOST_STRING-1);
            clienthost[MAX_HOST_STRING-1] = '\0';
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-n") == 0) {
            assert(argc >= 2);
            num_pkts = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-p") == 0) {
            assert(argc >= 2);
            rate = 1000000 / atol(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-r") == 0 ||
                   strcmp(argv[0], "--rate") == 0) {
            assert(argc >= 2);
            rate = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-ea") == 0 ||
                   strcmp(argv[0], "--exp-arrivals") == 0) {
            exp_arrivals = 1;
        } else if (strcmp(argv[0], "-rdr") == 0 ||
                   strcmp(argv[0], "--ramp-delta-rate") == 0) {
            assert(argc >= 2);
            ramp_delta_rate = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-rns") == 0 ||
                   strcmp(argv[0], "--ramp-num-steps") == 0) {
            assert(argc >= 2);
            ramp_num_steps = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-rss") == 0 ||
                   strcmp(argv[0], "--ramp-step-secs") == 0) {
            assert(argc >= 2);
            ramp_step_secs = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-rfn") == 0 ||
                   strcmp(argv[0], "--ramp-file-name") == 0) {
            assert(argc >= 2);
            ramp_fname = argv[1];
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-C") == 0 ||
                   strcmp(argv[0], "--comp-time") == 0) {
            assert(argc >= 2);
            comptimes_us = atoi(argv[1]);

            template_cmds[ncmd].cmd = COMPUTE;
            template_cmds[ncmd].u.comp_time_us = comptimes_us;

            ccmd_add(ccmd, &template_cmds[ncmd++]);

            n_compute++;
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-S") == 0 ||
                   strcmp(argv[0], "--store-data") == 0) {
            assert(argc >= 2);
            store_nbytes = atoi(argv[1]);


            template_cmds[ncmd].cmd = STORE;
            template_cmds[ncmd].u.store_nbytes = store_nbytes;

            ccmd_add(ccmd, &template_cmds[ncmd++]);

            n_store++;
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-L") == 0 ||
                   strcmp(argv[0], "--load-data") == 0) {
            assert(argc >= 2);
            load_nbytes = atoi(argv[1]);

            template_cmds[ncmd].cmd = LOAD;
            template_cmds[ncmd].u.load_nbytes = load_nbytes;

            ccmd_add(ccmd, &template_cmds[ncmd++]);

            return_bytes += load_nbytes;

            n_load++;
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-F") == 0 ||
                   strcmp(argv[0], "--forward") == 0) {
            assert(argc >= 2);

            struct sockaddr_in addr;
            host_net_config(argv[1], &addr);

            template_cmds[ncmd].cmd = FORWARD;
            template_cmds[ncmd].u.fwd.fwd_port = ntohs(addr.sin_port);
            template_cmds[ncmd].u.fwd.fwd_host = addr.sin_addr.s_addr;
            ccmd_add(ccmd, &template_cmds[ncmd++]);

            template_cmds[ncmd].cmd = REPLY;
            ccmd_add(ccmd, &template_cmds[ncmd++]);

            argc--;
            argv++;
        } else if (strcmp(argv[0], "-Cw") == 0 ||
                   strcmp(argv[0], "--comp-weight") == 0) {
            assert(argc >= 2);
            weights[COMPUTE] = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-Sw") == 0 ||
                   strcmp(argv[0], "--store-weight") == 0) {
            assert(argc >= 2);
            weights[STORE] = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-Lw") == 0 ||
                   strcmp(argv[0], "--load-weight") == 0) {
            assert(argc >= 2);
            weights[LOAD] = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-ec") == 0 ||
                   strcmp(argv[0], "--exp-comp") == 0) {
            exp_comptimes = 1;
        } else if (strcmp(argv[0], "-ws") == 0 ||
                   strcmp(argv[0], "--waitspin") == 0) {
            wait_spinning = 1;
        } else if (strcmp(argv[0], "-pso") == 0 ||
                   strcmp(argv[0], "--per-session-output") == 0) {
            per_session_output = 1;
        } else if (strcmp(argv[0], "-ps") == 0 ||
                   strcmp(argv[0], "--pkt-size") == 0) {
            assert(argc >= 2);
            pkt_size = atol(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-eps") == 0 ||
                   strcmp(argv[0], "--exp-pkt-size") == 0) {
            exp_pkt_size = 1;
        } else if (strcmp(argv[0], "-rs") == 0 ||
                   strcmp(argv[0], "--resp-size") == 0) {
            assert(argc >= 2);
            resp_size = atol(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-ers") == 0 ||
                   strcmp(argv[0], "--exp-resp-size") == 0) {
            exp_resp_size = 1;
        } else if (strcmp(argv[0], "-nd") == 0 ||
                   strcmp(argv[0], "--no-delay") == 0) {
            assert(argc >= 2);
            no_delay = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-nt") == 0 ||
                   strcmp(argv[0], "--num-threads") == 0) {
            assert(argc >= 2);
            num_threads = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-ns") == 0 ||
                   strcmp(argv[0], "--num-sessions") == 0) {
            assert(argc >= 2);
            num_sessions = atoi(argv[1]);
            check(num_sessions >= 1);
            argc--;
            argv++;
        } else {
            printf("Unrecognized option: %s\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        argc--;
        argv++;
    }

    // TODO: trunc pkt/resp size to BUF_SIZE when using the --exp- variants.
    template_cmds[ncmd].cmd = REPLY;
    template_cmds[ncmd].u.fwd.pkt_size = return_bytes;
    ccmd_last_reply(ccmd, &template_cmds[ncmd++]);

    // globals
    if (n_compute + n_store + n_load > 0 && num_pkts <= 0){
        num_pkts = 1;
    }

    for (int i = 0; i < 3; i++) {
        sum_w += weights[i];
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
            rate = rates[0];
            if (num_pkts == 0 || num_pkts > cnt) num_pkts = cnt;
        } else {
            num_pkts = 0;
            int r = rate;
            for (int s = 0; s < ramp_num_steps; s++) {
                num_pkts += r * ramp_step_secs;
                r += ramp_delta_rate;
            }
        }
    }

    host_net_config(serverhost, &serveraddr);
    host_net_config(clienthost, &myaddr);

    /* Set all bits of the padding field to 0 */
    memset(myaddr.sin_zero, '\0', sizeof(myaddr.sin_zero));

    num_pkts = (num_pkts + num_sessions - 1) / num_sessions * num_sessions;
    pkts_per_session = num_pkts / num_sessions;

    assert(num_pkts <= MAX_PKTS ||
           (per_session_output && pkts_per_session <= MAX_PKTS));

    printf("Configuration:\n");
    printf("  clienthost=%s\n", clienthost);
    printf("  serverhost=%s\n", serverhost);
    printf("  num_threads: %d\n", num_threads);
    printf("  num_pkts=%lu (COMPUTE:%d, STORE:%d, LOAD:%d)\n", num_pkts,
           n_compute, n_store, n_load);
    printf("  rate=%d, exp_arrivals=%d\n", rate, exp_arrivals);
    printf("  waitspin=%d\n", wait_spinning);
    printf("  ramp_num_steps=%d, ramp_delta_rate=%d, ramp_step_secs=%d\n",
           ramp_num_steps, ramp_delta_rate, ramp_step_secs);
    printf("  comptime_us=%lu, exp_comptimes=%d\n", comptimes_us,
           exp_comptimes);
    printf("  pkt_size=%lu (%lu with headers), exp_pkt_size=%d\n", pkt_size,
           pkt_size + TCPIP_HEADERS_SIZE, exp_pkt_size);
    printf("  resp_size=%lu (%lu with headers), exp_resp_size=%d\n", resp_size,
           resp_size + TCPIP_HEADERS_SIZE, exp_resp_size);
    printf("  min packet size due to header: send=%lu, reply=%lu\n",
           MIN_SEND_SIZE, MIN_REPLY_SIZE);
    printf("  max packet size: %d\n", BUF_SIZE);
    printf("  no_delay: %d\n", no_delay);
    printf("  num_sessions: %d\n", num_sessions);
    printf("  per_session_output: %d\n", per_session_output);

    assert(pkt_size >= MIN_SEND_SIZE);
    assert(pkt_size <= BUF_SIZE);
    assert(resp_size >= MIN_REPLY_SIZE);
    assert(resp_size <= BUF_SIZE);
    assert(no_delay == 0 || no_delay == 1);

    // Init random number generator
    srand(time(NULL));



    for (int i = 0; i < MAX_THREADS; i++) clientSocket[i] = -1;

    // Remember in ts_start the abs start time of the experiment
    clock_gettime(clk_id, &ts_start);

    for (int i = 0; i < num_threads; i++)
        assert(pthread_create(&receiver[i], NULL, thread_receiver,
                              (void *)(unsigned long)i) == 0);

    for (int i = 0; i < num_threads; i++) pthread_join(receiver[i], NULL);

    cw_log("Joined sender and receiver threads, exiting\n");

    return 0;
}

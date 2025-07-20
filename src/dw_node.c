#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h> /* See NOTES */
#include <unistd.h>
#include <stdbool.h>
#include <sys/prctl.h>
#include <argp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "dw_debug.h"
#include "message.h"
#include "timespec.h"
#include "thread_affinity.h"
#include "priority_queue.h"
#include "sched_attr.h"
#include "request.h"
#include "connection.h"
#include "address_utils.h"
#include "dw_poll.h"

#define MAX_EVENTS 10

volatile uint8_t running = 1;

// whether there's at least one bind address with SSL enabled
int ssl_enable = 0;
SSL_CTX *server_ssl_ctx = NULL;

static inline uint64_t i2l(uint32_t ln, uint32_t rn) {
    return ((uint64_t) ln) << 32 | rn;
}

static inline void l2i(uint64_t n, uint32_t* ln, uint32_t* rn) {
    if (ln)
        *ln = n >> 32;
    
    if (rn)
        *rn = (uint32_t) n;
}

typedef enum {
    LISTEN,
    STORAGE,
    TIMER,
    CONNECT,
    SOCKET,
    DISPATCH,
    STATS,
    TERMINATION,
    EVENT_NUMBER
} event_t;

const char* get_event_str(event_t event) {
    static char *event_str[EVENT_NUMBER] = {
        "LISTEN",
        "STORAGE",
        "TIMER",
        "CONNECT",
        "SOCKET",
        "DISPATCH",
        "STATS",
        "TERMINATION"
    };
    return event_str[event];
}

// used with --per-client-thread
#define MAX_THREADS 256
#define MAX_STORAGE_PATH_STR 100

#define MAX_LISTEN_SOCKETS 16
static int n_bind_addrs = 0;
static struct {
    char nodehostport[MAX_HOSTPORT_STRLEN];
    proto_t protocol;
} bind_addrs[MAX_LISTEN_SOCKETS] = {
    [0 ... MAX_LISTEN_SOCKETS-1] = { .nodehostport = DEFAULT_ADDR ":" DEFAULT_PORT, .protocol = TCP }
};

typedef struct {
    int listen_socks[MAX_LISTEN_SOCKETS];
    proto_t listen_socks_proto[MAX_LISTEN_SOCKETS];
    int n_listen_socks;

    int timerfd;        // special timerfd to handle forward timeouts
    int statfd;         // special signalfd to print statistics
    dw_poll_t dw_poll;

    pqueue_t *timeout_queue;
    int time_elapsed;

    // communication between parent and children conn workers (AM_PARENT only)
    // 0 is used for writing (parent), 1 for reading (child)
    int dispatchfd[2];

    // communication with storage
    int storefd; // write
    int store_replyfd; // read

    int worker_id;
    int core_id; // core pinning
    struct sched_attr sched_attrs;

    // load-balancing stats
    atomic_int active_conns;
    atomic_int active_reqs;
} conn_worker_info_t;

typedef struct {
    int storage_fd;
    char storage_path[MAX_STORAGE_PATH_STR];

    int use_odirect;

    size_t max_storage_size;
    size_t storage_offset; //TODO: mutual exclusion here to avoid race conditions in per-client thread mode
    size_t storage_eof; //TODO: same here
} storage_info_t;

typedef struct {
    int timerfd; // special timerfd to handle periodic storage sync
    int periodic_sync_msec;

    // communication with conn worker
    int storefd[MAX_THREADS]; // read
    int store_replyfd[MAX_THREADS]; //write

    pqueue_t* sync_waiting_queue; // worker threads waiting for periodic timer to be triggered
    int core_id; // core pinning

    storage_info_t storage_info;
    unsigned char *store_buf;
} storage_worker_info_t;

typedef struct {
    int worker_id;
    int req_id;
    command_t cmd;
    union {
        load_opts_t load_opts;
        store_opts_t store_opts;
    };
} storage_req_t;

pthread_t workers[MAX_THREADS];
conn_worker_info_t conn_worker_infos[MAX_THREADS];

// Pipe comm
int fds[MAX_THREADS][2];
int fds2[MAX_THREADS][2];

pthread_t storer;
storage_worker_info_t storage_worker_info;

//pthread_mutex_t socks_mtx;

int conn_threads = 1;
int no_delay = 1;
atomic_int next_thread_cnt = 0;
int use_wait_spinning = 0;
int enable_defrag = 1;

typedef enum { AM_CHILD, AM_SHARED, AM_PARENT } accept_mode_t;
accept_mode_t accept_mode = AM_CHILD;
dw_poll_type_t poll_mode = DW_EPOLL;
int listen_backlog = 5;

int terminationfd; // special signalfd to handle termination

// -1: old frequency-invariant behavior
//  0: automatically compute calibration value, store it to ~/.dw_loops_per_usec, and reload it from there
// >0: set explicitly calibration value
double loops_per_usec = -1.0;

int safe_write(int fd, unsigned char *buf, size_t len) {
    while (len > 0) {
        int written;
        if ((written = write(fd, buf, len)) < 0) {
            perror("write() failed");
            return -1;
        }
        buf += written;
        len -= written;
    }

    return 0;
}

int safe_read(int fd, unsigned char *buf, size_t len) {
    size_t len_on_last_seek = 0;
    while (len > 0) {
        ssize_t received = read(fd, buf, len);
        if (received < 0) {
            perror("read() failed");
            return -1;
        }

        if (received == 0) {
            if (len_on_last_seek > 0 && len_on_last_seek == len)
                break;
            lseek(fd, 0, SEEK_SET);
            len_on_last_seek = len;
            continue;
        }

        buf += received;
        len -= received;
    }

    return 0;
}

void insert_timeout(conn_worker_info_t* infos, int req_id, dw_poll_t *p_poll, int micros) {
    data_t data = {.value = req_id};
    req_info_t *req = req_get_by_id(req_id);
    int new_micros = micros;

    if (req == NULL)
        return;

    if (req->timeout_node) {
        dw_log("TIMEOUT already inserted, req_id: %d\n", req_id);
        return;
    }

    if (pqueue_size(infos->timeout_queue) > 0) {
        struct itimerspec timerspec = {0};
        sys_check(timerfd_gettime(infos->timerfd, &timerspec));
        new_micros += infos->time_elapsed;
        new_micros += pqueue_node_key(pqueue_top(infos->timeout_queue));
        new_micros -= its_to_us(timerspec);
    } else {
        infos->time_elapsed = 0;
    }

    req->timeout_node = pqueue_insert(infos->timeout_queue, new_micros, data);
    if (req->timeout_node == pqueue_top(infos->timeout_queue)) {
        struct itimerspec timerspec = us_to_its(micros);
        sys_check(timerfd_settime(infos->timerfd, 0, &timerspec, NULL));
    }

    dw_log("TIMEOUT inserted, req_id: %d, timeout: %dus\n", req_id, micros);
}

// remove a timeout from a request and returns the time remained before timeout
int remove_timeout(conn_worker_info_t* infos, int req_id, dw_poll_t *p_poll) {
    req_info_t *req = req_get_by_id(req_id);
    if (!req || !req->timeout_node)
        return -1;

    node_t *top = pqueue_top(infos->timeout_queue);
    struct itimerspec timerspec = {0};
    int time_elapsed, req_timeout;
    bool is_top = (top == req->timeout_node);

    req_timeout = pqueue_node_key(req->timeout_node);
    sys_check(timerfd_gettime(infos->timerfd, &timerspec));
    time_elapsed = pqueue_node_key(top) - its_to_us(timerspec);

    pqueue_remove(infos->timeout_queue, req->timeout_node);
    req->timeout_node = NULL;

    if (!is_top) {
        dw_log("TIMEOUT removed, req_id: %d, unqueued\n", req_id);
        return req_timeout - time_elapsed;
    }

    if (pqueue_size(infos->timeout_queue) > 0) {
        int next_timeout = pqueue_node_key(pqueue_top(infos->timeout_queue));
        sys_check(timerfd_gettime(infos->timerfd, &timerspec));
        infos->time_elapsed = time_elapsed;
        timerspec = us_to_its(next_timeout - time_elapsed);
        sys_check(timerfd_settime(infos->timerfd, 0, &timerspec, NULL));
        dw_log("TIMEOUT removed, req_id: %d, next interrupt: %dus\n", req_id, next_timeout - time_elapsed);
    } else {
        infos->time_elapsed = 0;
        timerspec = us_to_its(0);
        sys_check(timerfd_settime(infos->timerfd, 0, &timerspec, NULL));
        dw_log("TIMEOUT removed, req_id: %d, timer disarmed.\n", req_id);

    }

    return req_timeout - time_elapsed;
}

void setnonblocking(int fd);

int find_forward_reply_id(command_t *cmd, struct sockaddr_in from_addr);

// cmd_id is the index of the FORWARD item within m->cmds[] here, we
// remove the first (cmd_id+1) commands from cmds[], and forward the
// rest to the next hop
//
// returns the cmd after the forward if forward successfully started, or NULL if a problem occurred
command_t *single_start_forward(req_info_t *req, message_t *m, command_t *cmd, dw_poll_t *p_poll, conn_worker_info_t *infos) {
    fwd_opts_t fwd = *cmd_get_opts(fwd_opts_t, cmd);

    struct sockaddr_in addr;
    memset((char *) &addr, '\0', sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = fwd.fwd_host;
    addr.sin_port = fwd.fwd_port;

    int fwd_reply_id = find_forward_reply_id(req->curr_cmd, addr);
    if (fwd_reply_id == -1)
        return NULL;
    if (req->fwd_replies_left != -1 && (req->fwd_replies_mask & (1 << fwd_reply_id))) {
        // avoid retransmissions of already acknowledged FORWARD branches
        dw_log("Found reply for fwd to: %s:%d\n", inet_ntoa((struct in_addr) {addr.sin_addr.s_addr}), ntohs(addr.sin_port));
        cmd = cmd_next_forward(cmd);
        if (cmd == NULL) {
            cmd_log(cmd_skip(req->curr_cmd, 1));
        } else
            cmd_log(cmd);
        return cmd == NULL ? cmd_skip(req->curr_cmd, 1) : cmd;
    }
    int fwd_conn_id = conn_find_existing(addr, fwd.proto);
    if (fwd_conn_id == -1) {
        int clientSocket = 0;

        if (fwd.proto == TCP || fwd.proto == TLS) {
            clientSocket = socket(AF_INET, SOCK_STREAM, 0);
            sys_check(setsockopt(clientSocket, IPPROTO_TCP,
                                 TCP_NODELAY, (void *)&no_delay,
                                 sizeof(no_delay)));
        } else {
            clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
        }

        setnonblocking(clientSocket);
        fwd_conn_id = conn_alloc(clientSocket, addr, fwd.proto);
        if (fwd_conn_id == -1) {
            fprintf(stderr, "conn_alloc() failed, closing\n");
            close(clientSocket);
            return NULL;
        }

        conn_get_by_id(fwd_conn_id)->enable_defrag = enable_defrag;
        if (fwd.proto == TCP || fwd.proto == TLS) {
            check(dw_poll_add(p_poll, clientSocket, DW_POLLOUT | DW_POLLIN, i2l(CONNECT, fwd_conn_id)) == 0);

            dw_log("connecting to: %s:%d\n", inet_ntoa((struct in_addr) { addr.sin_addr.s_addr }),
                   ntohs(addr.sin_port));

            if (fwd.proto == TLS) {
                if (conn_enable_ssl(fwd_conn_id, server_ssl_ctx, 0) < 0) {
                    fprintf(stderr, "SSL_connect() failed on forward connection\n");
                    close(clientSocket);
                    conn_free(fwd_conn_id);
                    return NULL;
                }
            }

            int rv = connect(clientSocket, &addr, sizeof(addr));
            if (rv == -1) {
                if (errno != EAGAIN && errno != EINPROGRESS) {
                    dw_log("unexpected error from connect(): %s\n", strerror(errno));
                    return NULL;
                }

                dw_log("connect(): %s\n", strerror(errno));
                // normal case of asynchronous connect
                if (fwd.proto == TLS) {
                    conn_set_status_by_id(fwd_conn_id, SSL_HANDSHAKE);
                } else {
                    conn_set_status_by_id(fwd_conn_id, CONNECTING);
                }
            } else {
                dw_log("connect(): Ready\n");
                if (fwd.proto == TLS) {
                    conn_set_status_by_id(fwd_conn_id, SSL_HANDSHAKE);
                } else {
                    conn_set_status_by_id(fwd_conn_id, READY);
                    infos->active_conns++;
                }
            }
        }
    }

    int sock = conns[fwd_conn_id].sock;
    assert(sock != -1);
    message_t *m_dst = conn_prepare_send_message(&conns[fwd_conn_id]);
    assert(m_dst->req_size >= fwd.pkt_size);

    // skip possible FORWARD_CONTINUE cmds in non-branched multi-fwd
    command_t *c = cmd_next(cmd);
    while (c->cmd == FORWARD_CONTINUE)
        c = cmd_next(c);

    command_t* reply_cmd = message_copy_tail(m, m_dst, c);
    if (!reply_cmd) {
        dw_log("message_copy_tail(): destination message out-of-space\n");
        return NULL;
    }

    m_dst->req_id = req->req_id;
    m_dst->req_size = fwd.pkt_size;

    dw_log("Forwarding req %u to %s:%d\n", m_dst->req_id,
           inet_ntoa((struct in_addr) { fwd.fwd_host }),
           ntohs(fwd.fwd_port));
#ifdef DW_DEBUG
    msg_log(m_dst, "  f: ");
#endif

    if (conn_start_send(&conns[fwd_conn_id], addr) < 0)
        return NULL;
        
    if (req->fwd_timeout) {
        insert_timeout(infos, req->req_id, p_poll, req->fwd_timeout);
    }
    return cmd;
}

// return ptr to the cmd after the entire MULTI_FORWARD if OK, or NULL if an error occurred in at least one forward operation
command_t *start_forward(req_info_t *req, message_t *m, command_t *cmd, dw_poll_t *p_poll, conn_worker_info_t *infos) {
    assert(cmd->cmd == FORWARD_BEGIN || cmd->cmd == FORWARD_CONTINUE);
    if (req->fwd_replies_left == -1) {
        req->fwd_replies_left = cmd_get_opts(fwd_opts_t, cmd)->n_ack;
        req->fwd_replies_mask = 0;
        req->fwd_timeout = cmd_get_opts(fwd_opts_t, cmd)->timeout;
        req->fwd_retries = cmd_get_opts(fwd_opts_t, cmd)->retries;
        req->fwd_on_fail_skip = cmd_get_opts(fwd_opts_t, cmd)->on_fail_skip;

        dw_log("Starting FORWARD context for req:%d with nack:%d, timeout:%d, retry:%d\n", req->req_id, req->fwd_replies_left, req->fwd_timeout, req->fwd_retries);
    }
    
    command_t* itr = cmd;
    while (itr) {
        if (!single_start_forward(req, m, itr, p_poll, infos))
            return NULL;
        itr = cmd_next_forward(itr);
    }
    return cmd;
}

int process_messages(req_info_t *req, dw_poll_t *p_poll, conn_worker_info_t* infos);
int obtain_messages(int conn_id, dw_poll_t *p_poll, conn_worker_info_t* infos);

// return 0-based id if found, or -1 if not found
int find_forward_reply_id(command_t *cmd, struct sockaddr_in from_addr) {
    int id = 0;
    for (; cmd != NULL; cmd = cmd_next_forward(cmd), id++) {
        if (cmd_get_opts(fwd_opts_t, cmd)->fwd_host == from_addr.sin_addr.s_addr
            && cmd_get_opts(fwd_opts_t, cmd)->fwd_port == from_addr.sin_port)
            return id;
    }
    return -1;
}

// Call this once we received a REPLY from a socket matching a req_id we forwarded
int handle_forward_reply(int req_id, dw_poll_t *p_poll, conn_worker_info_t* infos, msg_status_t fwd_m_status, struct sockaddr_in from_addr) {
    req_info_t *req = req_get_by_id(req_id);

    if (!req) {
        dw_log("Could not match a response to FORWARD, req_id:%d - Dropped\n", req_id);
        return -1;
    }

    int reply_id = find_forward_reply_id(req->curr_cmd, from_addr);
    dw_log("Found reply_id %d from: %s:%d (conn_id: %d)\n", reply_id,
           inet_ntoa((struct in_addr) {from_addr.sin_addr.s_addr}), ntohs(from_addr.sin_port), req->conn_id);
    if (reply_id == -1) {
        dw_log("Got a REPLY to FORWARD from an unexpected endpoint: %s:%d - Dropped",
               inet_ntoa((struct in_addr) {from_addr.sin_addr.s_addr}), ntohs(from_addr.sin_port));
        return -1;
    }
    
    if (req->fwd_replies_mask & (1 << reply_id))
        // already acknowledged, ignore
        return -1;
    req->fwd_replies_mask |= (1 << reply_id);

    if (--(req->fwd_replies_left) <= 0) {
        message_t *m = req_get_message(req);
        m->status = fwd_m_status;
        req->curr_cmd = cmd_skip(req->curr_cmd, 1);
        
        // reply mask reset 
        req->fwd_replies_mask = 0;
        req->fwd_replies_left = -1;
        req->fwd_timeout = 0;
        req->fwd_retries = 0;
        remove_timeout(infos, req_id, p_poll);
        dw_log("FORWARD for req_id:%d finished\n", req->req_id);
        return process_messages(req, p_poll, infos);
    }
    
    dw_log("Replies_left: %d for req_id:%d\n", req->fwd_replies_left, req->req_id);
    return -1;
}

// returns 1 if reply sent correctly, 0 otherwise
int reply(req_info_t *req, message_t *m, command_t *cmd, conn_worker_info_t* infos) {
    message_t *m_dst = conn_prepare_send_message(&conns[req->conn_id]);
    reply_opts_t *opts = cmd_get_opts(reply_opts_t, cmd);
    assert(m_dst->req_size >= opts->resp_size);

    m_dst->req_id = m->req_id;
    m_dst->req_size = opts->resp_size;
    m_dst->cmds[0].cmd = EOM;
    m_dst->status = m->status;

    dw_log("Replying to req %u (conn_id=%d)\n", m->req_id, req->conn_id);
#ifdef DW_DEBUG
    msg_log(m_dst, "REPLY ");
#endif

    conn_info_t *conn = conn_get_by_id(req->conn_id);
    // cannot access req after conn_req_remove()
    int conn_id = req->conn_id;
    struct sockaddr_in target = req->target;
    conn_req_remove(conn, req);
    infos->active_reqs--;
    return conn_start_send(&conns[conn_id], target);
}

void compute_for_freqinv(unsigned long usecs) {
    struct timespec ts_beg, ts_end;
    dw_log("COMPUTE: computing for %lu usecs\n", usecs);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_beg);
    do {
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_end);
    } while (running && ts_sub_us(ts_end, ts_beg) < usecs);
}

unsigned long __attribute__((optimize("O0"))) loop() {
    long acc = 0;
    for (int i = 0; i < 100; i++)
        /* coverity[dont_call] */
        acc += rand();
    return acc;
}

double __attribute__((optimize("O0"))) compute_loops_per_usec() {
    unsigned long elapsed_min_ns = 0;
    struct timespec ts_beg, ts_end;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_beg);
    for (int i = 0; i < 100000; i++) {
        if (!running)
            break;
        loop();
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_end);
        unsigned long elapsed_ns = ts_sub_ns(ts_end, ts_beg);
        if (elapsed_min_ns == 0 || elapsed_ns < elapsed_min_ns)
            elapsed_min_ns = elapsed_ns;
        ts_beg = ts_end;
    }
    return elapsed_min_ns > 0 ? 1000.0 / elapsed_min_ns : 0;
}

void compute_for(unsigned long usecs) {
    if (loops_per_usec == -1.0) {
        compute_for_freqinv(usecs);
        return;
    }

    unsigned long nloops = usecs * loops_per_usec;
    dw_log("COMPUTE: computing for %lu usecs (nloops %ld)\n", usecs, nloops);

    unsigned long elapsed_min_ns = 0;
    struct timespec ts_beg, ts_end;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_beg);
    for (int i = 0; i < nloops; i++) {
        if (!running)
            break;
        loop();
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_end);
        unsigned long elapsed_ns = ts_sub_ns(ts_end, ts_beg);
        if (elapsed_min_ns == 0 || elapsed_ns < elapsed_min_ns)
            elapsed_min_ns = elapsed_ns;
        ts_beg = ts_end;
    }
}

// Needed to perform writes with O_DIRECT and ensure that:
// 1) the store buffer is aligned
// 2) the write is divisible by the block size
// (Essential, since O_DIRECT bypasses the page caches)
unsigned long blk_size = 0;

void store(storage_worker_info_t *infos, unsigned char* buf, store_opts_t *store_opts) {
    storage_info_t* storage_info = &(infos->storage_info);

    size_t total_bytes = store_opts->store_nbytes;
    uint32_t offset = store_opts->offset;
    uint8_t wait_sync = store_opts->wait_sync;

    // Round-up total_bytes to the nearest multiple of blk_size when using O_DIRECT
    if (storage_info->use_odirect) {
        total_bytes = (total_bytes + blk_size - 1) / blk_size * blk_size;
        offset = (offset + blk_size - 1) / blk_size * blk_size;
    }

    if (offset != -1) {
        if (lseek(storage_info->storage_fd, offset, SEEK_SET) < 0) {
            perror("lseek() failed");
            return; // @todo propagate error
        }
        storage_info->storage_offset = offset;
    } else {
        if (storage_info->storage_offset + total_bytes > storage_info->max_storage_size) {
            lseek(storage_info->storage_fd, 0, SEEK_SET);
            storage_info->storage_offset = 0;
        }
    }  

    dw_log("STORE: storing %lu bytes from %d offset\n", total_bytes, (int) storage_info->storage_offset);


    size_t stored_bytes = 0;
    size_t bytes = 0;
    while (stored_bytes < total_bytes) {
        bytes = (total_bytes - stored_bytes > BUF_SIZE) ? BUF_SIZE : (total_bytes - stored_bytes);
        check(safe_write(storage_info->storage_fd, buf, bytes) != -1);

        stored_bytes += bytes;
    }
    storage_info->storage_offset += total_bytes;

    if (wait_sync && infos->periodic_sync_msec <= 0) { 
        fsync(storage_info->storage_fd);
    }

    if (storage_info->storage_offset > storage_info->storage_eof) {
        storage_info->storage_eof = storage_info->storage_offset;

        if (storage_info->storage_eof > storage_info->max_storage_size) {
            storage_info->storage_eof = storage_info->max_storage_size;
        }
    }
}

void load(storage_worker_info_t *infos, unsigned char* buf, load_opts_t *load_opts) {
    storage_info_t* storage_info = &(infos->storage_info);

    size_t total_bytes = load_opts->load_nbytes;
    uint32_t offset = load_opts->offset;

    dw_log("LOAD: loading %lu bytes from %d offset\n", total_bytes, (int) offset);
    if (offset != -1) {
        if (lseek(storage_info->storage_fd, offset, SEEK_SET) < 0) {
            perror("lseek() failed");
            return; // @todo propagate error
        }
        storage_info->storage_offset = offset;
    } else {
        if (storage_info->storage_offset + total_bytes > storage_info->storage_eof) {
            lseek(storage_info->storage_fd, 0, SEEK_SET);
            storage_info->storage_offset = 0;
        }
    }

    size_t read_bytes = 0;
    size_t bytes = 0;
    while (read_bytes < total_bytes) {
        bytes = (total_bytes - read_bytes > BUF_SIZE) ? BUF_SIZE : (total_bytes - read_bytes);
        check(safe_read(storage_info->storage_fd, buf, bytes) != -1);
        if (bytes == 0)
            break;

        read_bytes += bytes;
    }
    storage_info->storage_offset += total_bytes;
}

// this invalidates the conn_info_t in conns[] referring sock, if any
void close_and_forget(dw_poll_t *p_poll, int sock) {
    dw_log("removing sock=%d from dw_poll\n", sock);
    if (dw_poll_del(p_poll, sock) != 0)
        perror("dw_poll_del() failed while deleting socket");
    dw_log("removing sock=%d from conns[]\n", sock);
    conn_del_sock(sock);
    close(sock);
}

// returns 1 if the message has been completely executed, 0 if the message need more time, -1 if some error occured
int process_single_message(req_info_t *req, dw_poll_t *p_poll, conn_worker_info_t *infos) {
    message_t *m = req_get_message(req);
    int conn_id = req->conn_id;

    for (command_t *cmd = req->curr_cmd; cmd->cmd != EOM; cmd = cmd_skip(cmd, 1)) {
        dw_log("PROCESS conn_id: %d, req_id: %d,  command: %s\n", req->conn_id, req->req_id, get_command_name(cmd->cmd));
        switch(cmd->cmd) {
        case COMPUTE:
            compute_for(cmd_get_opts(comp_opts_t, cmd)->comp_time_us);
            break;
        case FORWARD_BEGIN:
            // leave req->curr_cmd pointing to the FORWARD_BEGIN cmd, useful in case of retransmissions on timeout
            req->curr_cmd = cmd;
            // fall-through on purpose
        case FORWARD_CONTINUE:
            if (start_forward(req, m, cmd, p_poll, infos) == NULL) {
                fprintf(stderr, "Error: could not execute FORWARD\n");
                return -1;
            }
            return 0;
        case REPLY:
            dw_log("Handling REPLY: req_id=%d\n", m->req_id);
            if (conn_get_status_by_id(req->conn_id) != CLOSE && !reply(req, m, cmd, infos)) {
                fprintf(stderr, "reply() failed, conn_id: %d\n", conn_id);
                return -1;
            }
            // any further cmds[] for replied-to hop, not me
            return 1;
        case STORE:
        case LOAD: {
            storage_req_t w = { .worker_id = infos->worker_id, .req_id = req->req_id };
            int cmds_len = ((unsigned char*)cmd_next(cmd) - (unsigned char*)cmd);
            memcpy(&w.cmd, cmd, cmds_len);

            if (safe_write(infos->storefd, (unsigned char*) &w, sizeof(w)) < 0) {
                perror("storage worker write() failed");
                return -1;
            }

            if (cmd->cmd == STORE && !cmd_get_opts(store_opts_t, cmd)->wait_sync)
                break;

            req->curr_cmd = cmd_next(cmd);
            return 0; }
        default:
            fprintf(stderr, "Error: Unknown cmd: %d\n", m->cmds[0].cmd);
            return 0;
        }
    }

    return 1;
}

int process_messages(req_info_t *req, dw_poll_t *p_poll, conn_worker_info_t *infos) {
    // process_single_message() may call reply() -> conn_req_remove() -> req_unlink() + defrag -> req and m invalid
    int conn_id = req->conn_id;
    int executed = process_single_message(req, p_poll, infos);
    if (executed && conns[conn_id].serialize_request)
        return obtain_messages(conn_id, p_poll, infos);
    return executed;
}

int obtain_messages(int conn_id, dw_poll_t *p_poll, conn_worker_info_t* infos) {
    conn_info_t *conn = conn_get_by_id(conn_id);

    // batch processing of multiple messages, if received more than 1
    if (conn->serialize_request && conn->req_list != NULL)
        return 1;

    for (message_t *m = conn_prepare_recv_message(conn); m != NULL; m = conn_prepare_recv_message(conn)) {
        // FORWARD finished
        if (message_first_cmd(m)->cmd == EOM) {
            dw_log("Handling response to FORWARD from %s:%d, req_id=%d\n", inet_ntoa((struct in_addr) {conns[conn_id].target.sin_addr.s_addr}), 
                                                                           ntohs(conns[conn_id].target.sin_port), m->req_id);
            if (!handle_forward_reply(m->req_id, p_poll, infos, m->status, conns[conn_id].target)) {
                    dw_log("handle_forward_reply() failed\n");
                    return 0;
            }
        } else {
            req_info_t *req = conn_req_add(conn);
            if (req == NULL) {
                fprintf(stderr, "conn_req_add() failed\n");
                return 0;
            }
            infos->active_reqs++;

            req->message_ptr = (unsigned char*) m;
            req->curr_cmd = message_first_cmd(m);
            // process_single_message() may call reply() -> conn_req_remove() -> req_unlink() + defrag -> req and m invalid
            int req_size = m->req_size;
            int executed = process_single_message(req, p_poll, infos);

            if (executed < 0)
                return 0;

            if (!executed && conns[conn_id].serialize_request) {
                conns[conn_id].curr_proc_buf += req_size;
                return 1;
            }
        }
    }

    return 1;
}

int establish_conn(dw_poll_t *p_poll, int conn_id) {
    int val;
    socklen_t len = sizeof(val);
    sys_check(getsockopt(conns[conn_id].sock, SOL_SOCKET, SO_ERROR, (void*)&val, &len));
    if (val != 0) {
        dw_log("getsockopt() reported connect() failure: %s\n", strerror(val));
        return 0;
    }
    // this may trigger send_messages() on return, if messages have already been enqueued
    conn_set_status_by_id(conn_id, READY);

    sys_check(dw_poll_mod(p_poll, conns[conn_id].sock, DW_POLLIN, i2l(SOCKET, conn_id)));

    return 1;
}

void setnonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    assert(flags >= 0);
    flags |= O_NONBLOCK;
    sys_check(fcntl(fd, F_SETFL, flags));
}

// @TODO: in case of multi-forward (branched or not), this has to distinguish among who replied and who not, rather than just counting retries in req->fwd_retries
void handle_timeout(dw_poll_t *p_poll, conn_worker_info_t *infos) {
    struct itimerspec disarmspec = {0};
    disarmspec = us_to_its(0);

    if (!pqueue_size(infos->timeout_queue)) {
        sys_check(timerfd_settime(infos->timerfd, 0, &disarmspec, NULL));
        dw_log("Empty TIMEOUT queue, timer disarmed.\n");
        return;
    }

    int req_id = pqueue_node_data(pqueue_top(infos->timeout_queue)).value;
    req_info_t *req = req_get_by_id(req_id);
    if (!req) {
        sys_check(timerfd_settime(infos->timerfd, 0, &disarmspec, NULL));
        dw_log("Request req_id: %d missing, timer disarmed.\n", req_id);
        return;
    }
    
    message_t *m = req_get_message(req);
    conn_info_t *conn = conn_get_by_id(req->conn_id);

    remove_timeout(infos, req_id, p_poll);

    // command_t *p_cmd = req->curr_cmd;
    // if curr_cmd is no more on FORWARD_CONTINUE, ignore
    // TODO: case with 2 independent (non-nested) forwards in same req
    //if (p_cmd->cmd != FORWARD_BEGIN && p_cmd->cmd != FORWARD_CONTINUE) // || m->req_id != req_id)
    //    return;

    dw_log("on_fail_skip=%d\n", req->fwd_on_fail_skip);
    if (req->fwd_retries > 0) {
        dw_log("TIMEOUT expired, req_id: %d, retry: %d\n", req->req_id, req->fwd_retries);
        
        req->fwd_retries--;
        process_messages(req, p_poll, infos);
    } else if (req->fwd_on_fail_skip > 0) {
        dw_log("TIMEOUT expired, req_id: %d, failed, skipping: %d\n", req->req_id, req->fwd_on_fail_skip);
        
        req->curr_cmd = cmd_skip(req->curr_cmd, req->fwd_on_fail_skip);
        m->status = TIMEOUT;
        process_messages(req, p_poll, infos);
    } else {
        dw_log("TIMEOUT expired, req_id: %d, failed\n", req->req_id);

        m->status = TIMEOUT;
        conn_req_remove(conn, req);
        infos->active_reqs--;
    }
}

void exec_request(dw_poll_t *p_poll, dw_poll_flags pflags, int conn_id, event_t type, conn_worker_info_t* infos) {
    conn_info_t *conn = conn_get_by_id(conn_id);
    dw_log("event_type=%s, conn_id=%d\n", get_event_str(type), conn_id);

    if (conn->status == SSL_HANDSHAKE) {
        int hs = conn_do_ssl_handshake(conn_id);
        if (hs < 0)
            goto err;
        else if (hs == 0) {
            /* handshake still in progress, do not proceed with send/recv */
            return;
        }
        /* handshake is complete => status=READY => continue below */
    }

    if (type == TIMER) {
        handle_timeout(p_poll, infos);
        return;
    }

    if ((type == SOCKET || type == CONNECT) && (conn->sock == -1 || conn->recv_buf == NULL))
        return;

    if (pflags & DW_POLLERR || pflags & DW_POLLHUP) {
        dw_log("Connection to remote peer refused, conn_id=%d\n", conn_id);
        goto err;
    }

    if (pflags & DW_POLLIN) {
        dw_log("calling recv_mesg()\n");
        if (conn_recv(conn) == 0)
            goto err;
    }
    if ((pflags & DW_POLLOUT) && (type == CONNECT)) {
        dw_log("calling establish_conn()\n");
        if (!establish_conn(p_poll, conn_id))
            goto err;
        infos->active_conns++;
        // we need the send_messages() below to still be tried afterwards
    }
    if ((pflags & DW_POLLOUT) && conn->curr_send_size > 0 && conn_get_status(conn) != CONNECTING && conn_get_status(conn) != NOT_INIT) {
        dw_log("calling send_mesg() to conn_id=%d\n", conn_id);
        if (!conn_send(conn))
            goto err;
    }
    dw_log("conns[%d].status=%d (%s)\n", conn_id, conn_get_status(conn), conn_status_str(conn_get_status(conn)));

    // check whether we have new or leftover messages to process
    dw_log("calling obtain_messages() from conn_id=%d's recv buffer\n", conn_id)
    if (!obtain_messages(conn_id, p_poll, infos))
        goto err;

    if (conn->curr_send_size > 0 && conn_get_status(conn) == READY) {
        dw_log("adding EPOLLOUT for sock=%d, conn_id=%d, curr_send_size=%lu\n",
               conns->sock, conn_id, conns->curr_send_size);
        sys_check(dw_poll_mod(p_poll, conns->sock, DW_POLLIN | DW_POLLOUT, i2l(SOCKET, conn_id)));
        conn_set_status(conn, SENDING);
    }
    if (conn->curr_send_size == 0 && conn_get_status(conn) == SENDING) {
        dw_log("removing EPOLLOUT for sock=%d, conn_id=%d, curr_send_size=%lu\n",
               conn->sock, conn_id, conn->curr_send_size);
        sys_check(dw_poll_mod(p_poll, conns->sock, DW_POLLIN, i2l(SOCKET, conn_id)));
        conn_set_status(conn, READY);
        infos->active_conns++;
    }

    return;

 err:
    if (conns->proto == TCP && conn_get_status(conn) == READY) {
        infos->active_conns--;
    }
    close_and_forget(p_poll, conn->sock);

    // Close associated connections
    for (int i = 0; i < MAX_CONNS; i++) {
        conn_info_t *pending_conn = conn_get_by_id(i);
        if (pending_conn->sock == -1)
            continue;

        req_info_t* req_list_head = pending_conn->req_list;
        req_info_t* tmp = req_list_head;
        while (tmp != NULL) {
            message_t* m = req_get_message(tmp);
            if (tmp->curr_cmd->cmd == FORWARD_BEGIN) {
                fwd_opts_t fwd = *cmd_get_opts(fwd_opts_t, tmp->curr_cmd);
                if (fwd.fwd_host == conn->target.sin_addr.s_addr &&
                        fwd.fwd_port == conn->target.sin_port) {
                    
                    if (fwd.retries > 0)
                        break;
                    else
                        remove_timeout(infos, m->req_id, p_poll);
                        
                    // Go to last REPLY
                    command_t *itr = tmp->curr_cmd;
                    while (itr->cmd != EOM && itr->cmd != REPLY)
                        itr = cmd_skip(tmp->curr_cmd, 1);

                    if (itr->cmd == EOM) { // brutal
                        close_and_forget(p_poll, pending_conn->sock);
                    } else { // graceful
                        tmp->curr_cmd = itr;
                        m->status = ERR;
                        process_messages(tmp, p_poll, infos);
                    }
                    break;
                }
            }
            tmp = tmp->next;
            if (tmp == req_list_head) {
                break;
            }
        }
    }
}

void* storage_worker(void* args) {
    storage_worker_info_t *infos = (storage_worker_info_t *)args;
    infos->sync_waiting_queue = pqueue_alloc(MAX_REQS);

    sprintf(thread_name, "storagew");
    sys_check(prctl(PR_SET_NAME, thread_name, NULL, NULL, NULL));

    if (infos->core_id >= 0) {
        sys_check(aff_pin_to(infos->core_id));
        dw_log("thread %ld pinned to core %i\n", pthread_self(), infos->core_id);
    }

    dw_poll_t poll, *p_poll = &poll;

    check(dw_poll_init(p_poll, poll_mode) == 0);

    // Add conn_worker(s) -> storage_worker communication pipe
    for (int i = 0; i < conn_threads; i++) {
        if (dw_poll_add(p_poll, infos->storefd[i], DW_POLLIN, i2l(STORAGE, infos->storefd[i])) != 0)
            perror("dw_epoll_add(): storefd failed");
    }

    // Add termination handler
    if (dw_poll_add(p_poll, terminationfd, DW_POLLIN, i2l(TERMINATION, terminationfd)) < 0)
        perror("dw_poll_add(): terminationfd failed");

    // Add periodic sync timerfd
    if (infos->periodic_sync_msec > 0) {
        if ((infos->timerfd = timerfd_create(CLOCK_BOOTTIME, 0)) < 0) {
            perror("timerfd_create");
            exit(EXIT_FAILURE);
        }

        struct itimerspec its;
        memset(&its, 0, sizeof(its));

        struct timespec ts_template;
        ts_template.tv_sec =  infos->periodic_sync_msec / 1000;
        ts_template.tv_nsec = (infos->periodic_sync_msec % 1000) * 1000000;

        //both interval and value have been set
        its.it_value = ts_template;
        its.it_interval = ts_template;

        if (timerfd_settime(infos->timerfd, 0, &its, NULL) < 0) {
            perror("timerfd_settime");
            exit(EXIT_FAILURE);
        }

        if (dw_poll_add(p_poll, infos->timerfd, DW_POLLIN, i2l(TIMER, infos->timerfd)) < 0)
            perror("dw_poll_add(): timerfd failed");
    }

    while (running) {
        int nfds = dw_poll_wait(p_poll);
        if (nfds == -1) {
            perror("dw_poll_wait() returned error");

            if (errno != EINTR) {
                perror("dw_poll_wait() failed (storage_worker): ");
                exit(EXIT_FAILURE);
            }
        }

        int fd;
        uint64_t aux;
        event_t type;
        dw_poll_flags pflags;
        while ((dw_poll_next(p_poll, &pflags, &aux)) != 0) {
            l2i(aux, (uint32_t*)&type, (uint32_t*) &fd);

            if (type == TERMINATION) {
                dw_log("TERMINATION\n");
                running = 0;
                break;
            } else if (type == TIMER) {
                // NOTE: timerfd requires a read to be re-armed
                uint64_t val;
                if (read(infos->timerfd, &val, sizeof(uint64_t)) < 0) {
                    perror("periodic sync read()");
                    running = 0;
                    break;
                }

                fsync(infos->storage_info.storage_fd);

                while (pqueue_size(infos->sync_waiting_queue) > 0) {
                    int worker_id = pqueue_node_key(pqueue_top(infos->sync_waiting_queue));
                    int req_id = pqueue_node_data(pqueue_top(infos->sync_waiting_queue)).value;

                    pqueue_pop(infos->sync_waiting_queue);
                    safe_write(infos->store_replyfd[worker_id], (unsigned char*) &req_id, sizeof(req_id));
                }

                // Too expensive??
                dw_log("storage sync...\n");
            } else if (type == STORAGE) {
                storage_req_t w;
                int worker_id;
                int req_id;

                if (safe_read(fd, (unsigned char*) &w, sizeof(w)) < 0) {
                    perror("storage worker safe_read()");
                    running = 0;
                    break;
                }

                worker_id = w.worker_id;
                req_id = w.req_id;

                dw_log("STORAGE cmd from conn_id %d\n", req_id);
                
                if (w.cmd.cmd == STORE) {
                    store(infos, infos->store_buf, cmd_get_opts(store_opts_t, &w.cmd));
                    if (cmd_get_opts(store_opts_t, &w.cmd)->wait_sync) { 
                        if (infos->periodic_sync_msec <= 0) {
                            safe_write(infos->store_replyfd[worker_id], (unsigned char*) &req_id, sizeof(req_id));
                        } else {
                            data_t data = {.value=req_id};
                            pqueue_insert(infos->sync_waiting_queue, worker_id, data);
                        }
                    }
                } else if (w.cmd.cmd == LOAD) {
                    load(infos, infos->store_buf, cmd_get_opts(load_opts_t, &w.cmd));
                    safe_write(infos->store_replyfd[worker_id], (unsigned char*) &req_id, sizeof(req_id));
                } else { // error
                    fprintf(stderr, "Unknown command sent to storage server - skipping");
                }
            } else {
                fprintf(stderr, "Unknown event in storage server - skipping");
            }
        }
    }

    return (void*)1;
}

void* conn_worker(void* args) {
    conn_worker_info_t *infos = (conn_worker_info_t *)args;

    sprintf(thread_name, "connw-%d", infos->worker_id);
    sys_check(prctl(PR_SET_NAME, thread_name, NULL, NULL, NULL));

    if (infos->core_id >= 0) {
        sys_check(aff_pin_to(infos->core_id));
        dw_log("thread %ld pinned to core %i\n", pthread_self(), infos->core_id);
    }

    sys_check(sched_setattr(0, &infos->sched_attrs, 0));

    if (accept_mode != AM_PARENT || infos == &conn_worker_infos[0]) {
        for (int i = 0; i < infos->n_listen_socks; i++) {
            int s = infos->listen_socks[i];
            if (s < 0) continue;
            int conn_id = conn_find_sock(s);

            uint64_t aux;
            if(conn_id == -1) // TCP/TLS
                aux = i2l(LISTEN, s);
            else // UDP
                aux = i2l(SOCKET, conn_id);
            check(dw_poll_add(&infos->dw_poll, s, DW_POLLIN, aux) == 0);
        }
    }

    // Add termination fd
    check(dw_poll_add(&infos->dw_poll, terminationfd, DW_POLLIN, i2l(TERMINATION, terminationfd)) == 0);

    // Add timer fd
    check(dw_poll_add(&infos->dw_poll, infos->timerfd, DW_POLLIN, i2l(TIMER, infos->timerfd)) == 0);

    // Add stat fd
    if (infos->statfd != -1)
        check(dw_poll_add(&infos->dw_poll, infos->statfd, DW_POLLIN, i2l(STATS, infos->statfd)) == 0);

    // Add storage reply fd
    if (infos->storefd != -1)
        check(dw_poll_add(&infos->dw_poll, infos->store_replyfd, DW_POLLIN, i2l(STORAGE, infos->store_replyfd)) == 0);

    // Add parent communication fd
    if (accept_mode == AM_PARENT) {
        check(dw_poll_add(&infos->dw_poll, infos->dispatchfd[1], DW_POLLIN, i2l(DISPATCH, infos->dispatchfd[1])) == 0);
    }

    while (running) {
        int nfds = dw_poll_wait(&infos->dw_poll);
        if (nfds == -1) {
            perror("dw_poll_wait()");

            if (errno != EINTR) {
                perror("dw_poll_wait() failed (conn_worker): ");
                exit(EXIT_FAILURE);
            }
        }

        uint64_t aux;
        dw_poll_flags pflags;
        while (dw_poll_next(&infos->dw_poll, &pflags, &aux)) {
            int event_data;
            event_t event_type;
            l2i(aux, &event_type, (uint32_t*) &event_data);
            dw_log("event_type=%s, event_data=%d (conn_id if event_type==SOCKET, polled fd otherwise)\n", get_event_str(event_type), event_data);
            
            if (event_type == LISTEN) { // New connection (TCP or TLS)
                struct sockaddr_in addr;
                socklen_t addr_size = sizeof(addr);
                int conn_sock;
                sys_check(conn_sock = accept(event_data, (struct sockaddr *)&addr, &addr_size));

                dw_log("Accepted connection from: %s:%d\n",
                       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                setnonblocking(conn_sock);
                sys_check(setsockopt(conn_sock, IPPROTO_TCP, TCP_NODELAY,
                                     (void *)&no_delay, sizeof(no_delay)));

                // find the index of the listening socket to read the protocol
                int sock_index = -1;
                for (int k = 0; k < infos->n_listen_socks; k++) {
                    if (infos->listen_socks[k] == event_data) {
                        sock_index = k;
                        break;
                    }
                }
                if (sock_index < 0) {
                    fprintf(stderr, "Error: cannot find listening sock index\n");
                    close(conn_sock);
                    continue;
                }
                proto_t p = infos->listen_socks_proto[sock_index];

                int conn_id = conn_alloc(conn_sock, addr, p);
                if (conn_id < 0) {
                    fprintf(stderr, "Could not allocate new conn_info_t, closing...\n");
                    close_and_forget(&infos->dw_poll, conn_sock);
                    continue;
                }

                if (p == TLS) {
                    if (conn_enable_ssl(conn_id, server_ssl_ctx, 1) < 0) {
                        fprintf(stderr, "SSL_accept() failed on incoming connection\n");
                        close_and_forget(&infos->dw_poll, conn_sock);
                        conn_free(conn_id);
                        continue;
                    }
                } else
                    conn_set_status_by_id(conn_id, READY);

                conn_get_by_id(conn_id)->enable_defrag = enable_defrag;
                infos->active_conns++;
                
                int next_thread_id = accept_mode == AM_PARENT ? (atomic_fetch_add(&next_thread_cnt, 1) % conn_threads) : (infos - conn_worker_infos);
                if (accept_mode == AM_PARENT && infos->dw_poll.poll_type != DW_EPOLL) { // NOTE: in AM_PARENT mode, only the parent worker thread will reach here
                    int rv = write(conn_worker_infos[next_thread_id].dispatchfd[0], (unsigned char*) &conn_id, sizeof(conn_id));
                    if (rv == -1)
                        perror("sock dispatch write():");
                    if (rv < sizeof(conn_id))
                        fprintf(stderr, "sock dispatch write(): message too long\n");
                } else {
                    if (dw_poll_add(&conn_worker_infos[next_thread_id].dw_poll, conn_sock, DW_POLLIN, i2l(SOCKET, conn_id)) != 0)
                        perror("dw_poll() failed");
                }
                dw_log("conn_id: %d assigned to connw-%d\n", conn_id, next_thread_id);
            } else if (event_type == STORAGE) {
                check(event_data == infos->store_replyfd);

                int req_id_ACK;
                if (safe_read(infos->store_replyfd, (unsigned char*) &req_id_ACK, sizeof(req_id_ACK)) < 0) {
                    perror("storage worker read() failed");
                    continue;
                }

                dw_log("STORAGE ACK for req_id %d\n", req_id_ACK);
                if (req_get_by_id(req_id_ACK))
                    process_messages(req_get_by_id(req_id_ACK), &infos->dw_poll, infos);
                else
                    dw_log("Could not find req_info_t for req_id_ACK %d\n", req_id_ACK);
            } else if (event_type == DISPATCH) {
                check(event_data == infos->dispatchfd[1]);

                int conn_id;
                int rv = read(event_data, (unsigned char*) &conn_id, sizeof(conn_id));
                if (rv == -1) {
                    perror("sock dispatch read():");
                    continue;
                }
                if (rv < sizeof(conn_id)) {
                    fprintf(stderr, "sock dispatch write(): message too long\n");
                    continue;
                }

                conn_info_t *conn = conn_get_by_id(conn_id);
                if (dw_poll_add(&infos->dw_poll, conn->sock, DW_POLLIN, i2l(SOCKET, conn_id)) != 0)
                    perror("dw_poll() failed");
            } else if (event_type == TERMINATION) {
                // no need to disarm signal, since we are killing the node anyway
                dw_log("TERMINATION\n");
                running = 0;
                break;
            } else if (event_type == STATS) {
                // disarm signal
                struct signalfd_siginfo sfdi;
                if (read(event_data, &sfdi, sizeof(struct signalfd_siginfo)) != sizeof(struct signalfd_siginfo)) {
                    perror("signal read");
                    running = 0;
                    break;
                }

                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);

                int total_active_conns = 0;
                int total_active_reqs = 0;
                for (int i = 0; i < conn_threads; i++) {
                    total_active_conns += conn_worker_infos[i].active_conns;
                    total_active_reqs  += conn_worker_infos[i].active_reqs;
                    printf("[%ld.%09ld][%s] STATS worker-id: %d, active-conns: %d, active-reqs: %d\n", ts.tv_sec, ts.tv_nsec, 
                                                                                            thread_name, conn_worker_infos[i].worker_id, 
                                                                                            conn_worker_infos[i].active_conns, conn_worker_infos[i].active_reqs);
                }
                printf("[%ld.%09ld][%s] STATS total-active-conns: %d, total-active-reqs: %d\n", ts.tv_sec, ts.tv_nsec, thread_name, 
                                                                                            total_active_conns, total_active_reqs);

                break;
            } else {
                exec_request(&infos->dw_poll, pflags, event_data, event_type, infos);
            }
        }
    }

    return (void *)1;
}

enum argp_node_option_keys {
    HELP = 'h',
    USAGE = 0x100,
    BIND_ADDR = 'b',
    ACCEPT_MODE = 'a',
    POLL_MODE = 'p',
    STORAGE_OPT_ARG = 's',
    MAX_STORAGE_SIZE = 'm',
    THREAD_AFFINITY = 'c',
    NUM_THREADS = 0x101,
    SCHED_POLICY = 0x102,
    SYNC,
    ODIRECT,
    NO_DEFRAG,
    NO_DELAY,
    WAIT_SPIN,
    LOOPS_PER_USEC,
    BACKLOG_LENGTH,
    SSL_CERT_FILE,
    SSL_KEY_FILE,
    SSL_CA_FILE,
    SSL_CIPHERS,
    SSL_CA_PATH,
    SSL_VERIFY
};

struct argp_node_arguments {
    int periodic_sync_msec;
    size_t max_storage_size;
    int use_odirect;
    int use_thread_affinity;
    char* thread_affinity_list;
    int num_threads;
    struct sched_attr sched_attrs;
    char* ssl_cert;
    char* ssl_key;
    char* ssl_ca;
    char* ssl_ciphers;
    char* ssl_ca_path;
    int ssl_verify;
};

static struct argp_option argp_node_options[] = {
    // long name, short name, value name, flag, description
    {"bind-addr",         BIND_ADDR,        "[tcp|udp|ssl:[//]][host][:port]",0,  "DistWalk node bindname, bindport, and communication protocol (can be specified multiple times)"},
    {"accept-mode",       ACCEPT_MODE,      "child|shared|parent",            0,  "Accept mode (per-worker thread, shared or parent-only listening queue)"},
    {"poll-mode",         POLL_MODE,        "epoll|poll|select",              0,  "Poll mode (defaults to epoll)"},
    {"backlog-length",    BACKLOG_LENGTH,   "n",                              0,  "Maximum pending connections queue length"},
    {"bl",                BACKLOG_LENGTH,   "n", OPTION_ALIAS},
    {"storage",           STORAGE_OPT_ARG,  "path/to/storage/file",           0,  "Path to the file used for storage"},
    {"max-storage-size",  MAX_STORAGE_SIZE, "nbytes",                         0,  "Max size for the storage size"},
    {"nt",                NUM_THREADS,      "n",                              0,  "Number of threads dedicated to communication" },
    {"num-threads",       NUM_THREADS,      "n", OPTION_ALIAS },
    {"sync",              SYNC,             "msec",                           0,  "Periodically sync the written data on disk" },
    {"odirect",           ODIRECT,           0,                               0,  "Enable direct disk access (bypass read/write OS caches)"},
    {"thread-affinity",   THREAD_AFFINITY,  "auto|cX,cZ[,cA-cD[:step]]",      0,  "Thread-to-core pinning (automatic or user-defined list using taskset syntax)"},
    {"sched-policy",      SCHED_POLICY,     "other[:nice]|rr:rtprio|fifo:rtprio|dl:runtime_us,dline_us", 0,  "Scheduling policy (defaults to other)"},
    {"no-delay",          NO_DELAY,         "0|1",                            0,  "Set value of TCP_NODELAY socket option"},
    {"nd",                NO_DELAY,         "0|1", OPTION_ALIAS },
    {"no-defrag",         NO_DEFRAG,         0,                               0,  "Disable defragmentation of connection buffers for incoming messages (defaults to defrag enabled)"},
    {"wait-spin",         WAIT_SPIN,         0,                               0,  "Spin-wait instead of sleeping till next received packet"},
    {"ws",                WAIT_SPIN,         0, OPTION_ALIAS },
    {"loops-per-usec",    LOOPS_PER_USEC,    "value",                         0,  "Set loops_per_usec calibration parameter (0: handle it automatically in ~/.dw_loops_per_usec; -1: use frequency-invariant mode)"},
    {"help",              HELP,              0,                               0,  "Show this help message", 1 },
    {"usage",             USAGE,             0,                               0,  "Show a short usage message", 1 },
    {"ssl-cert",          SSL_CERT_FILE,     "FILE",                          0,  "Server SSL certificate file" },
    {"ssl-key",           SSL_KEY_FILE,      "FILE",                          0,  "Server SSL key file" },
    {"ssl-ca",            SSL_CA_FILE,       "FILE",                          0,  "Server SSL CA file" },
    {"ssl-ciphers",       SSL_CIPHERS,       "CIPHERS",                       0,  "Allowed SSL ciphers" },
    {"ssl-ca-path",       SSL_CA_PATH,       "DIR",                           0,  "Server SSL CA path" },
    {"ssl-verify",        SSL_VERIFY,        0,                               0,  "Enable peer certificate verification"},
    { 0 }
};

static error_t argp_node_parse_opt(int key, char *arg, struct argp_state *state) {
    /* Get the input argument from argp_parse, which we
        know is a pointer to our arguments structure. */
    struct argp_node_arguments *arguments = state->input;

    switch(key) {
    case HELP:
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
        break;
    case USAGE:
        argp_state_help(state, state->out_stream, ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK);
        break;
    case BIND_ADDR:
        if (n_bind_addrs >= MAX_LISTEN_SOCKETS) {
            fprintf(stderr, "Too many --bind-addr options\n");
            exit(EXIT_FAILURE);
        }
        addr_proto_parse(arg, bind_addrs[n_bind_addrs].nodehostport, &bind_addrs[n_bind_addrs].protocol);
        n_bind_addrs++;
        break;
    case ACCEPT_MODE:
        if (strcmp(arg, "child") == 0)
            accept_mode = AM_CHILD;
        else if (strcmp(arg, "shared") == 0)
            accept_mode = AM_SHARED;
        else if (strcmp(arg, "parent") == 0)
            accept_mode = AM_PARENT;
        else {
            printf("Invalid accept mode parameter: %s\n", arg);
            exit(EXIT_FAILURE);
        }
        break;
    case POLL_MODE:
        if (strcmp(arg, "epoll") == 0)
            poll_mode = DW_EPOLL;
        else if (strcmp(arg, "poll") == 0)
            poll_mode = DW_POLL;
        else if (strcmp(arg, "select") == 0)
            poll_mode = DW_SELECT;
        else {
            printf("Invalid poll mode parameter: %s\n", arg);
            exit(EXIT_FAILURE);
        }
        break;
    case BACKLOG_LENGTH:
        listen_backlog = atoi(arg);
        break;
    case NO_DELAY:
        no_delay = atoi(arg);
        check(no_delay == 0 || no_delay == 1);
        break;
    case NO_DEFRAG:
        enable_defrag = 0;
        break;
    case WAIT_SPIN:
        use_wait_spinning = 1;
        break;
    case LOOPS_PER_USEC:
        loops_per_usec = atof(arg);
        check(loops_per_usec == -1 || loops_per_usec >= 0);
        break;
    case STORAGE_OPT_ARG:
        if (strlen(arg) >= MAX_STORAGE_PATH_STR) {
            printf("storage_path too long: %s\n", arg);
            exit(EXIT_FAILURE);
        }
        strcpy(storage_worker_info.storage_info.storage_path, arg);
        break;
    case SYNC:
        arguments->periodic_sync_msec = atoi(arg);
        break;
    case MAX_STORAGE_SIZE:
        arguments->max_storage_size = atol(arg);
        break;
    case NUM_THREADS:
        arguments->num_threads = atoi(arg);
        break;
    case ODIRECT:
        arguments->use_odirect = 1;
        break;
    case THREAD_AFFINITY:
        arguments->use_thread_affinity = 1;
        if (strcmp(arg, "auto") != 0) {
            arguments->thread_affinity_list = arg;
        }
        break;
    case SCHED_POLICY:
        if (strncmp(arg, "other", 5) == 0) {
            arguments->sched_attrs.sched_policy = SCHED_OTHER;
            int val;
            if (sscanf(arg + 5, ":%d", &val) == 1)
                arguments->sched_attrs.sched_nice = val;
            else
                check(arg[5] == 0, "Wrong syntax to --sched-policy=other");
        } else if (strncmp(arg, "rr", 2) == 0) {
            arguments->sched_attrs.sched_policy = SCHED_RR;
            int val;
            int rv = sscanf(arg + 2, ":%d", &val);
            check(rv == 1, "Wrong syntax for --sched-policy=rr");
            arguments->sched_attrs.sched_priority = val;
        } else if (strncmp(arg, "fifo", 4) == 0) {
            arguments->sched_attrs.sched_policy = SCHED_FIFO;
            int val;
            int rv = sscanf(arg + 4, ":%d", &val);
            check(rv == 1, "Wrong syntax for --sched-policy=fifo");
            arguments->sched_attrs.sched_priority = val;
        } else if (strncmp(arg, "dl", 2) == 0) {
            arguments->sched_attrs.sched_policy = SCHED_DEADLINE;
            unsigned long val, val2;
            int rv = sscanf(arg + 2, ":%lu,%lu", &val,&val2);
            check(rv == 2, "Wrong syntax for --sched-policy=dl");
            arguments->sched_attrs.sched_runtime = val * 1000;
            arguments->sched_attrs.sched_deadline = val2 * 1000;
            arguments->sched_attrs.sched_period = val2 * 1000;
        } else {
            fprintf(stderr, "Wrong argument to --sched-policy option\n");
            exit(EXIT_FAILURE);
        }
        break;
    case SSL_CERT_FILE:
        arguments->ssl_cert = arg;
        break;
    case SSL_KEY_FILE:
        arguments->ssl_key = arg;
        break;
    case SSL_CA_FILE:
        arguments->ssl_ca = arg;
        break;
    case SSL_CIPHERS:
        arguments->ssl_ciphers = arg;
        break;
    case SSL_CA_PATH:
        arguments->ssl_ca_path = arg;
        break;
    case SSL_VERIFY:
        arguments->ssl_verify = 1;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

void init_listen_sock(int i, accept_mode_t accept_mode, proto_t proto, struct sockaddr_in serverAddr) {
    if (accept_mode == AM_CHILD || i == 0) {
        int lsock;
        if (proto == TCP || proto == TLS) {
            sys_check(lsock = socket(AF_INET, SOCK_STREAM, 0));
        } else {
            sys_check(lsock = socket(AF_INET, SOCK_DGRAM, 0));
            int conn_id = conn_alloc(lsock, serverAddr, UDP);
            check(conn_id != -1, "conn_alloc() failed, terminating!");
            conn_set_status_by_id(conn_id, READY);
            conn_get_by_id(conn_id)->enable_defrag = enable_defrag;
        }
        int val = 1;
        sys_check(setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(val)));
        if (accept_mode == AM_CHILD)
            sys_check(setsockopt(lsock, SOL_SOCKET, SO_REUSEPORT, (void *)&val, sizeof(val)));

        /*---- Bind the address struct to the socket ----*/
        sys_check(bind(lsock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)));

        dw_log("Node bound to %s:%d (with protocol: %s)\n", inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), proto_str(proto));

        /*---- Listen on the socket, with 5 max connection requests queued ----*/
        /* For TLS => same as TCP. */
        if (proto == TCP || proto == TLS)
            sys_check(listen(lsock, listen_backlog));
        dw_log("Accepting new connections (max backlog: %d)...\n", listen_backlog);

        conn_worker_infos[i].listen_socks_proto[conn_worker_infos[i].n_listen_socks] = proto;
        conn_worker_infos[i].listen_socks[conn_worker_infos[i].n_listen_socks++] = lsock;
    } else if (accept_mode == AM_SHARED) {
        conn_worker_infos[i].n_listen_socks = conn_worker_infos[0].n_listen_socks;
        for (int k = 0; k < conn_worker_infos[0].n_listen_socks; k++) {
            conn_worker_infos[i].listen_socks[k] = conn_worker_infos[0].listen_socks[k];
            conn_worker_infos[i].listen_socks_proto[k] = conn_worker_infos[0].listen_socks_proto[k];
        }
    } else if (accept_mode == AM_PARENT) {
        conn_worker_infos[i].n_listen_socks = 0;
    }
}

int main(int argc, char *argv[]) {
    static struct argp argp = { argp_node_options, argp_node_parse_opt, 0, "Distwalk Node -- the server program" };
    struct argp_node_arguments input_args;
    
    // Default argp values
    input_args.periodic_sync_msec = -1;
    input_args.max_storage_size = 1024 * 1024 * 1024;
    input_args.use_odirect = 0;
    input_args.use_thread_affinity = 0;
    input_args.thread_affinity_list = NULL;    
    input_args.num_threads = 1;
    input_args.sched_attrs = (struct sched_attr) { .size = sizeof(struct sched_attr), .sched_policy = SCHED_OTHER, .sched_flags = 0 };
    input_args.ssl_cert = NULL;
    input_args.ssl_key = NULL;
    input_args.ssl_ca = NULL;
    input_args.ssl_ciphers = NULL;
    input_args.ssl_ca_path = NULL;
    input_args.ssl_verify = 0;

    char *home_path = getenv("HOME");
    check(home_path != NULL && strlen(home_path) + 10 < sizeof(storage_worker_info.storage_info));
    strcpy(storage_worker_info.storage_info.storage_path, home_path);
    strcat(storage_worker_info.storage_info.storage_path, "/.dw_store");
    storage_worker_info.storage_info.storage_fd = -1;

    argp_parse(&argp, argc, argv, ARGP_NO_HELP, 0, &input_args);
    
    // Handle SIGINT and SIGTERM via epoll
    sigset_t term_sigmask;
    sigemptyset(&term_sigmask);
    sigaddset(&term_sigmask, SIGTERM);
    sigaddset(&term_sigmask, SIGINT);
    sys_check(pthread_sigmask(SIG_BLOCK, &term_sigmask, 0));
    terminationfd = signalfd(-1, &term_sigmask, 0);

    // Handle SIGUSR1 via epoll (on thread_info[0] only)
    sigset_t stat_sigmask;
    sigemptyset(&stat_sigmask);
    sigaddset(&stat_sigmask, SIGUSR1);
    sys_check(pthread_sigmask(SIG_BLOCK, &stat_sigmask, 0));

    // Setup thread name
    sys_check(prctl(PR_GET_NAME, thread_name, NULL, NULL, NULL));
    
    cpu_set_t mask;
    struct sockaddr_in serverAddr;

    // Storage worker info defaults
    storage_worker_info.timerfd = -1;
    storage_worker_info.periodic_sync_msec = input_args.periodic_sync_msec;

    storage_worker_info.storage_info.max_storage_size = input_args.max_storage_size;
    storage_worker_info.storage_info.use_odirect = input_args.use_odirect;
    storage_worker_info.storage_info.storage_offset = 0; //TODO: mutual exclusion here to avoid race conditions in per-client thread mode
    storage_worker_info.storage_info.storage_eof = 0; //TODO: same here

    // Configure global variables
    conn_threads = input_args.num_threads;

    check(input_args.num_threads > 0 && input_args.num_threads <= MAX_THREADS, "--threads needs an argument between 1 and %d\n", MAX_THREADS);

    // Retrieve cpu set for thread-core pinning
    int core_it = 0;
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);

    dw_log("nproc=%ld (system capacity)\n", nproc);

    if (input_args.use_thread_affinity) {
        if (input_args.thread_affinity_list) {
            aff_list_parse(input_args.thread_affinity_list, &mask, nproc);
        } else {
            CPU_ZERO(&mask);
            sys_check(sched_getaffinity(0, sizeof(cpu_set_t), &mask));
        }

        // Point to first pinnable core
        core_it = aff_it_init(&mask, nproc);
    }

    conn_init();
    req_init();

    // If any bind address has TLS, we set ssl_enable = 1
    for (int i = 0; i < n_bind_addrs; i++) {
        if (bind_addrs[i].protocol == TLS) {
            ssl_enable = 1;
            break;
        }
    }

    // if we have TLS, create an SSL_CTX
    if (ssl_enable) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        server_ssl_ctx = SSL_CTX_new(TLS_method());
        if (!server_ssl_ctx) {
            fprintf(stderr, "Error: cannot create server SSL context\n");
            exit(EXIT_FAILURE);
        }
        if (input_args.ssl_ca && input_args.ssl_ca[0]) {
            if (!SSL_CTX_load_verify_locations(server_ssl_ctx, input_args.ssl_ca, NULL)) {
                fprintf(stderr, "Error: cannot load CA file '%s'\n", input_args.ssl_ca);
                exit(EXIT_FAILURE);
            }
        }
        if (input_args.ssl_ca_path && input_args.ssl_ca_path[0]) {
            if (!SSL_CTX_load_verify_locations(server_ssl_ctx, NULL, input_args.ssl_ca_path)) {
                fprintf(stderr, "Error: cannot load CA path '%s'\n", input_args.ssl_ca_path);
                exit(EXIT_FAILURE);
            }
        }
        if (input_args.ssl_cert && input_args.ssl_cert[0]) {
            if (SSL_CTX_use_certificate_file(server_ssl_ctx, input_args.ssl_cert, SSL_FILETYPE_PEM) <= 0) {
                fprintf(stderr, "Error: cannot load cert file '%s'\n", input_args.ssl_cert);
                exit(EXIT_FAILURE);
            }
        }
        if (input_args.ssl_key && input_args.ssl_key[0]) {
            if (SSL_CTX_use_PrivateKey_file(server_ssl_ctx, input_args.ssl_key, SSL_FILETYPE_PEM) <= 0) {
                fprintf(stderr, "Error: cannot load key file '%s'\n", input_args.ssl_key);
                exit(EXIT_FAILURE);
            }
        }
        if (input_args.ssl_ciphers && input_args.ssl_ciphers[0]) {
            if (!SSL_CTX_set_cipher_list(server_ssl_ctx, input_args.ssl_ciphers)) {
                fprintf(stderr, "Error: cannot set the desired SSL ciphers '%s'\n", input_args.ssl_ciphers);
                exit(EXIT_FAILURE);
            }
        }
        if (input_args.ssl_verify) {
            SSL_CTX_set_verify(server_ssl_ctx, SSL_VERIFY_PEER, NULL);
            SSL_CTX_set_verify_depth(server_ssl_ctx, 100);
        }
    }

    // Open storage file, if any
    if (storage_worker_info.storage_info.storage_path[0] != '\0') {
        int flags = O_RDWR | O_CREAT | O_TRUNC;
        if (storage_worker_info.storage_info.use_odirect)
            flags |= O_DIRECT;
        sys_check(storage_worker_info.storage_info.storage_fd = open(storage_worker_info.storage_info.storage_path, flags, S_IRUSR | S_IWUSR));
        sys_check(fallocate(storage_worker_info.storage_info.storage_fd, 0, 0, BUF_SIZE));

        struct stat s;
        sys_check(fstat(storage_worker_info.storage_info.storage_fd, &s));
        blk_size = s.st_blksize;
        dw_log("blk_size = %lu\n", blk_size);

        if (storage_worker_info.storage_info.use_odirect) { // block-aligned buffer
            sys_check(posix_memalign((void**) &storage_worker_info.store_buf, blk_size, BUF_SIZE));
        } else {
            storage_worker_info.store_buf = calloc(1, BUF_SIZE);
        }
        for (int i = 0; i < input_args.num_threads; i++) {
            // conn_worker -> storage_worker
            if (pipe(fds[i]) == -1) {
               perror("pipe");
               exit(EXIT_FAILURE);
            }

            storage_worker_info.storefd[i] = fds[i][0]; // read
            conn_worker_infos[i].storefd = fds[i][1]; // write

            // storage_worker -> conn_worker
            if (pipe(fds2[i]) == -1) {
               perror("pipe");
               exit(EXIT_FAILURE);
            }

            storage_worker_info.store_replyfd[i] = fds2[i][1]; // write 
            conn_worker_infos[i].store_replyfd = fds2[i][0]; // read
        }
    } else {
        for (int i = 0; i < input_args.num_threads; i++) {
            conn_worker_infos[i].storefd = -1;
            conn_worker_infos[i].store_replyfd = -1;
        }
    }

    if (loops_per_usec == 0.0) {
        char *dirname = getenv("HOME");
        if (!dirname)
            dirname = ".";
#ifdef DW_DEBUG
        char *lps_fname = ".dw_loops_per_usec_dbg";
#else
        char *lps_fname = ".dw_loops_per_usec";
#endif
        char *fname = malloc(strlen(dirname) + 2 + strlen(lps_fname));
        sprintf(fname, "%s/%s", dirname, lps_fname);
        FILE *f = fopen(fname, "r");
        if (f) {
            dw_log("Loading loops_per_sec from: %s\n", fname);
            if (fscanf(f, "%lf", &loops_per_usec) != 1)
                dw_log("Could not load loops_per_sec from: %s\n", fname);
            fclose(f);
        }
        if (loops_per_usec == 0.0) {
            loops_per_usec = compute_loops_per_usec();
            dw_log("Storing loops_per_sec to: %s\n", fname);
            FILE *f = fopen(fname, "w");
            fprintf(f, "%lf\n", loops_per_usec);
            fclose(f);
        }
    }
    dw_log("Using loops_per_usec: %g\n", loops_per_usec);

    // Initialize conn_worker_infos
    for (int i = 0; i < input_args.num_threads; i++) {
        /*---- Create the socket(s). The three arguments are: ----*/
        /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this
        * case) */

        conn_worker_infos[i].n_listen_socks = 0;

        check(dw_poll_init(&conn_worker_infos[i].dw_poll, poll_mode) == 0);
        conn_worker_infos[i].timerfd =  timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK);
        conn_worker_infos[i].timeout_queue = pqueue_alloc(MAX_REQS);
        conn_worker_infos[i].sched_attrs = input_args.sched_attrs;
        
        // TODO: Consider using a dedicated thread for statistics to avoid the edge-case
        //       where a single-threaded node is executing a long COMPUTE, thus
        //       preventing signals to be processed on time
        if (i == 0) {
            conn_worker_infos[i].statfd = signalfd(-1, &stat_sigmask, 0);
        } else {
            conn_worker_infos[i].statfd = -1;   
        }

        // Round-robin thread-core pinning
        if (input_args.use_thread_affinity) {
            conn_worker_infos[i].core_id = core_it;

            aff_it_next(&core_it, &mask, nproc);
        } else {
            conn_worker_infos[i].core_id = -1;
        }

        conn_worker_infos[i].worker_id = i;

        conn_worker_infos[i].active_conns = 0;
        conn_worker_infos[i].active_reqs = 0;

        // Auxiliary communication medium
        if (accept_mode == AM_PARENT) {
            sys_check(socketpair(AF_LOCAL, SOCK_STREAM, 0, conn_worker_infos[i].dispatchfd));
        } else {
            conn_worker_infos[i].dispatchfd[0] = -1;
            conn_worker_infos[i].dispatchfd[1] = -1;
        }
    }

    // Init socks mutex
    // TODO: change sock_add and sock_dell's logic to avoid lock re-entrancy
    //pthread_mutexattr_t attr;

    //pthread_mutexattr_init(&attr);
    //pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    //sys_check(pthread_mutex_init(&socks_mtx, &attr));

    if (n_bind_addrs == 0) {
        // user didn't provide --bind-addr => use default
        n_bind_addrs = 1;
    }

    // For each requested bind-addr, init the listen socket(s)
    for (int l = 0; l < n_bind_addrs; l++) {
        addr_parse(bind_addrs[l].nodehostport, &serverAddr);
        for (int i = 0; i < conn_threads; i++) {
            init_listen_sock(i, accept_mode, bind_addrs[l].protocol, serverAddr);
        }
    }

    // Init storage thread
    if (storage_worker_info.storage_info.storage_path[0] != '\0') {
        if (input_args.use_thread_affinity) {
            storage_worker_info.core_id = core_it;
            aff_it_next(&core_it, &mask, nproc);
        } else {
            storage_worker_info.core_id = -1;
        }
        sys_check(pthread_create(&storer, NULL, storage_worker, (void *)&storage_worker_info));
    }

    // Run
    if (input_args.num_threads == 1) {
        conn_worker((void*) &conn_worker_infos[0]);
    } else {
        // Init worker threads
        for (int i = 0; i < input_args.num_threads; i++) {
            sys_check(pthread_create(&workers[i], NULL, conn_worker, (void *)&conn_worker_infos[i]));
        }
    }
    
    // Clean-ups
    if (input_args.num_threads > 1) {
        // Join worker threads
        for (int i = 0; i < input_args.num_threads; i++) {
            sys_check(pthread_join(workers[i], NULL));
            pqueue_free(conn_worker_infos[i].timeout_queue);
        }

        //sys_check(pthread_mutex_destroy(&socks_mtx));
    } else {
        pqueue_free(conn_worker_infos[0].timeout_queue);
    }

    if (storage_worker_info.storage_info.storage_path[0] != '\0') {
        sys_check(pthread_join(storer, NULL));
        pqueue_free(storage_worker_info.sync_waiting_queue);
        free(storage_worker_info.store_buf);
    }

    // close terminationfd
    close(terminationfd);

    // termination clean-ups
    if (storage_worker_info.storage_info.storage_fd >= 0) {
        close(storage_worker_info.storage_info.storage_fd);

        for (int i = 0; i < input_args.num_threads; i++) {
            close(conn_worker_infos[i].storefd);
            close(storage_worker_info.storefd[i]);

            close(conn_worker_infos[i].store_replyfd);
            close(storage_worker_info.store_replyfd[i]);

            close(conn_worker_infos[i].dispatchfd[0]);
            close(conn_worker_infos[i].dispatchfd[1]);
        }
    }

    // cleanup server SSL context if allocated
    if (server_ssl_ctx) {
        SSL_CTX_free(server_ssl_ctx);
        server_ssl_ctx = NULL;
    }

    return 0;
}

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
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h> /* See NOTES */
#include <unistd.h>
#include <stdbool.h>

#include "cw_debug.h"
#include "message.h"
#include "timespec.h"
#include "thread_affinity.h"
#include "priority_queue.h"

#include "request.h"
#include "connection.h"

#define MAX_EVENTS 10

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
    TERMINATION,
    STORAGE,
    TIMER,
    CONNECT,
    SOCKET,
    EVENT_NUMBER
} event_t;

const char* get_event_str(event_t event) {
    static char event_str[EVENT_NUMBER][20] = {
        "LISTEN",
        "TERMINATION",
        "STORAGE",
        "TIMER",
        "CONNECT",
        "SOCKET"
    };
    return event_str[event];
}

// used with --per-client-thread
#define MAX_THREADS 32

typedef struct {
    int listen_sock;
    int terminationfd;  // special eventfd to handle termination
    int timerfd;

    pqueue_t *timeout_queue;
    int time_elapsed;

    // communication with storage
    int storefd; // write
    int store_replyfd; // read

    int worker_id;
    int core_id; // core pinning
} thread_info_t;

typedef struct {
    int storage_fd;

    int tfd; // periodic timerfd
    int periodic_sync_msec;

    size_t max_storage_size;
    size_t storage_offset; //TODO: mutual exclusion here to avoid race conditions in per-client thread mode
    size_t storage_eof; //TODO: same here

    // communication with conn worker
    int storefd[MAX_THREADS]; // read
    int store_replyfd[MAX_THREADS]; //write
    int nthread;

    unsigned char *store_buf;

    int terminationfd;
} storage_info_t;

typedef struct {
    command_t *cmd;
    int worker_id;
    int req_id;
} wrapper_t;

pthread_t workers[MAX_THREADS];
thread_info_t thread_infos[MAX_THREADS];

pthread_t storer;
storage_info_t storage_info;

pthread_mutex_t socks_mtx;


char *bind_name = "0.0.0.0";
int bind_port = 7891;

int no_delay = 1;

int use_odirect = 0;
int nthread = 1;
_Atomic volatile int running = 1;

int thread_affinity = 0;
char* thread_affinity_list;

#define MAX_STORAGE_SIZE 1000000
char *storage_path = NULL;


void sigint_cleanup(int _) {
    (void)_;  // to avoid unused var warnings

    running = 0;

    // terminate workers by sending a notification
    // on their terminationfd
    if (nthread > 1) {
        for (int i = 0; i < nthread; i++) {
            eventfd_write(thread_infos[i].terminationfd, 1);
        }
    }

    eventfd_write(storage_info.terminationfd, 1);
}

void safe_write(int fd, unsigned char *buf, size_t len) {
    while (len > 0) {
        int sent;
        if ((sent = write(fd, buf, len)) < 0) {
            perror("write() failed");
            return;
        }
        buf += sent;
        len -= sent;
    }
}

size_t safe_read(int fd, unsigned char *buf, size_t len) {
    size_t leftovers = len;

    while (leftovers > 0) {
        int received;
        if ((received = read(fd, buf, leftovers)) < 0) {
            perror("read() failed");
            return leftovers;
        }

        if (received == 0) {
            printf("read() EoF\n");
            break;
        }

        buf += received;
        leftovers -= received;
    }

    return leftovers;
}

int timerspec_to_micros(struct itimerspec t) {
    return t.it_value.tv_sec * 1000000 + t.it_value.tv_nsec / 1000;
}

struct itimerspec micros_to_timerspec(int micros) {
    struct itimerspec timerspec = {0};
    timerspec.it_value.tv_sec = (micros / 1000000);
    timerspec.it_value.tv_nsec = (micros % 1000000) * 1000;
    return timerspec;
}

void insert_timeout(thread_info_t* infos, int req_id, int epollfd, int micros) {
    data_t data = {.value=req_id};
    req_info_t *req = req_get_by_id(req_id);
    int new_micros = micros;

    if (req == NULL)
        return;

    if (pqueue_size(infos->timeout_queue) > 0) {
        struct itimerspec timerspec = {0};
        sys_check(timerfd_gettime(infos->timerfd, &timerspec));
        new_micros += infos->time_elapsed;
        new_micros += pqueue_node_key(pqueue_top(infos->timeout_queue));
        new_micros -= timerspec_to_micros(timerspec);
    } else {
        infos->time_elapsed = 0;
    }

    req->timeout_node = pqueue_insert(infos->timeout_queue, new_micros, data);
    if (req->timeout_node == pqueue_top(infos->timeout_queue)) {
        struct itimerspec timerspec = micros_to_timerspec(micros);
        sys_check(timerfd_settime(infos->timerfd, 0, &timerspec, NULL));
    }

    cw_log("TIMEOUT inserted, req_id: %d, timeout: %dus\n", req_id, micros);

}

// remove a timeout from a request and returns the time remained before timeout
int remove_timeout(thread_info_t* infos, int req_id, int epollfd) {
    req_info_t *req = req_get_by_id(req_id);
    if (!req || !req->timeout_node)
        return -1;

    pqueue_node_t *top = pqueue_top(infos->timeout_queue);
    struct itimerspec timerspec = {0};
    int time_elapsed, req_timeout;
    bool is_top = (top == req->timeout_node);

    req_timeout = pqueue_node_key(req->timeout_node);
    sys_check(timerfd_gettime(infos->timerfd, &timerspec));
    time_elapsed = pqueue_node_key(top) - timerspec_to_micros(timerspec);

    pqueue_remove(infos->timeout_queue, req->timeout_node);
    req->timeout_node = NULL;

    if (!is_top) {
        cw_log("TIMEOUT removed, req_id: %d, unqueued\n", req_id);
        return req_timeout - time_elapsed;
    }

    if (pqueue_size(infos->timeout_queue) > 0) {
        int next_timeout = pqueue_node_key(pqueue_top(infos->timeout_queue));
        sys_check(timerfd_gettime(infos->timerfd, &timerspec));
        infos->time_elapsed = time_elapsed;
        timerspec = micros_to_timerspec(next_timeout - time_elapsed);
        sys_check(timerfd_settime(infos->timerfd, 0, &timerspec, NULL));
        cw_log("TIMEOUT removed, req_id: %d, next interrupt: %dus\n", req_id, next_timeout - time_elapsed);
    } else {
        infos->time_elapsed = 0;
        timerspec = micros_to_timerspec(0);
        sys_check(timerfd_settime(infos->timerfd, 0, &timerspec, NULL));
        cw_log("TIMEOUT removed, req_id: %d, timer disarmed.\n", req_id);

    }

    return req_timeout - time_elapsed;
}

void setnonblocking(int fd);

// cmd_id is the index of the FORWARD item within m->cmds[] here, we
// remove the first (cmd_id+1) commands from cmds[], and forward the
// rest to the next hop
//
// returns number of forwarded commands as found in m, 0 if a problem occurred,
// or -1 if command cannot be completed now (asynchronous FORWARD)
int start_forward(req_info_t *req, message_t *m, command_t *cmd, int epollfd, thread_info_t *infos) {
    fwd_opts_t fwd = *cmd_get_opts(fwd_opts_t, cmd);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = fwd.fwd_host},
        .sin_port = fwd.fwd_port,
    };
    int fwd_conn_id = conn_find_existing(addr, fwd.proto);
    if (fwd_conn_id == -1) {
        int no_delay = 1;
        int clientSocket = 0;

        if (fwd.proto == TCP) {
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
            fprintf(stderr, "conn_add() failed, closing\n");
            close(clientSocket);
            return 0;
        }

        if (fwd.proto == TCP) {
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLONESHOT;
            ev.data.u64 = i2l(CONNECT, fwd_conn_id);
            cw_log("Adding fd %d to epollfd %d\n", clientSocket, epollfd);
            sys_check(epoll_ctl(epollfd, EPOLL_CTL_ADD, clientSocket, &ev));

            cw_log("connecting to: %s:%d\n", inet_ntoa((struct in_addr) {fwd.fwd_host}),
                   ntohs(fwd.fwd_port));
            memset((char *) &addr, '\0', sizeof(addr));

            int rv = connect(clientSocket, &addr, sizeof(addr));
            cw_log("connect() returned: %d (errno: %s)\n", rv, strerror(errno));
            if (rv == -1) {
                if (errno != EAGAIN && errno != EINPROGRESS) {
                    cw_log("unexpected error from connect(): %s\n", strerror(errno));
                    return 0;
                }
                // normal case of asynchronous connect
                conns[fwd_conn_id].status = CONNECTING;
            }
        }
    }

    int sock = conns[fwd_conn_id].sock;
    assert(sock != -1);
    message_t *m_dst = conn_send_message(&conns[fwd_conn_id]);
    assert(m_dst->req_size >= fwd.pkt_size);

    command_t *c = cmd_next(cmd);
    while (c->cmd != EOM && c->cmd == MULTI_FORWARD) {
        c = cmd_next(c);
    }

    command_t* reply_cmd = message_copy_tail(m, m_dst, c);
    m_dst->req_id = req->req_id;
    m_dst->req_size = fwd.pkt_size;

    cw_log("Forwarding req %u to %s:%d\n", m_dst->req_id,
           inet_ntoa((struct in_addr){fwd.fwd_host}),
           ntohs(fwd.fwd_port));
#ifdef CW_DEBUG
    msg_log(m_dst, "  f: ");
#endif
    cw_log("  f: cmds[] has %d items, pkt_size is %u\n", m_dst->num,
           m_dst->req_size);

    if (conn_start_send(&conns[fwd_conn_id], addr) < 0)
        return 0;
        
    if (fwd.timeout) {
        insert_timeout(infos, req->req_id, epollfd, fwd.timeout);
    }

    req->fwd_replies_left = cmd_get_opts(reply_opts_t, reply_cmd)->n_ack;

    return 1;
}

int process_messages(req_info_t *req, int epollfd, thread_info_t* infos);
int obtain_messages(int conn_id, int epollfd, thread_info_t* infos);

// Call this once we received a REPLY from a socket matching a req_id we forwarded
int handle_forward_reply(int req_id, int epollfd, thread_info_t* infos) {
    req_info_t *req = req_get_by_id(req_id);

    if (!req) {
        cw_log("Could not match a response to FORWARD, req_id=%d - Dropped\n", req_id);
        return 1;
    }

    cw_log("Found match with conn_id %d\n", req->conn_id);
        
    if (--(req->fwd_replies_left) <= 0) {
        message_t *m = req_get_message(req);

        req->curr_cmd = message_skip_cmds(m, req->curr_cmd, 1);
        
        remove_timeout(infos, req_id, epollfd);

        return process_messages(req, epollfd, infos);
    }
    
    return 1;
}

// returns 1 if reply sent correctly, 0 otherwise
int reply(req_info_t *req, message_t *m, command_t *cmd) {
    message_t *m_dst = conn_send_message(&conns[req->conn_id]);
    reply_opts_t *opts = cmd_get_opts(reply_opts_t, cmd);
    assert(m_dst->req_size >= opts->resp_size);

    cw_log("%d, m_dst: %p, send_buf: %p\n", req->conn_id, m_dst, conns[req->conn_id].send_buf);

    m_dst->req_id = m->req_id;
    m_dst->req_size = opts->resp_size;
    m_dst->num = 0;
    m_dst->cmds[0].cmd = EOM;

    cw_log("Replying to req %u (conn_id=%d)\n", m->req_id, req->conn_id);
    cw_log("  cmds[] has %d items, pkt_size is %u\n", m_dst->num,
           m_dst->req_size);
#ifdef CW_DEBUG
    msg_log(m_dst, "  ");
#endif

    conn_info_t *conn = conn_get_by_id(req->conn_id);
    conn_req_remove(conn, req);
    return conn_start_send(&conns[req->conn_id], req->target);
}

void compute_for(unsigned long usecs) {
    struct timespec ts_beg, ts_end;
    cw_log("COMPUTE: computing for %lu usecs\n", usecs);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_beg);
    do {
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_end);
    } while (ts_sub_us(ts_end, ts_beg) < usecs);
}

unsigned long blk_size = 0;

void store(storage_info_t* storage_info, unsigned char* buf, size_t bytes) {
    // generate the data to be stored
    if (use_odirect) bytes = (bytes + blk_size - 1) / blk_size * blk_size;
    cw_log("STORE: storing %lu bytes\n", bytes);

    //write, otherwise over-write
    if (storage_info->storage_offset + bytes > storage_info->max_storage_size) {
        lseek(storage_info->storage_fd, 0, SEEK_SET);
        storage_info->storage_offset = 0;
    }

    safe_write(storage_info->storage_fd, buf, bytes);

    storage_info->storage_offset += bytes;

    if (storage_info->periodic_sync_msec < 0)
        fsync(storage_info->storage_fd);

    if (storage_info->storage_offset > storage_info->storage_eof) {
        storage_info->storage_eof = storage_info->storage_offset;

        if (storage_info->storage_eof > storage_info->max_storage_size) {
            storage_info->storage_eof = storage_info->max_storage_size;
        }
    }
}

void load(storage_info_t* storage_info, unsigned char* buf, size_t bytes, size_t* leftovers) {
    cw_log("LOAD: loading %lu bytes\n", bytes);

    if (storage_info->storage_offset + bytes > storage_info->storage_eof) {
        lseek(storage_info->storage_fd, 0, SEEK_SET);
        storage_info->storage_offset = 0;
    }

    *leftovers = safe_read(storage_info->storage_fd, buf, bytes);
    storage_info->storage_offset += bytes;
}

// this invalidates the conn_info_t in conns[] referring sock, if any
void close_and_forget(int epollfd, int sock) {
    cw_log("removing sock=%d from epollfd\n", sock);
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, sock, NULL) == -1)
        perror("epoll_ctl() failed while deleting socket");
    cw_log("removing sock=%d from conns[]\n", sock);
    conn_del_sock(sock);
    close(sock);
}

// returns 1 if the message has been completely executed, 0 if the message need more time, -1 if some error occured
int process_single_message(req_info_t *req, int epollfd, thread_info_t *infos) {
    message_t *m = req_get_message(req);

    for (command_t *cmd = req->curr_cmd; cmd->cmd != EOM; cmd = cmd_next(cmd)) {
        cw_log("PROCESS req_id: %d,  command: %s\n", req->req_id, get_command_name(cmd->cmd));

        switch(cmd->cmd) {
        case COMPUTE:
            compute_for(cmd_get_opts(comp_opts_t, cmd)->comp_time_us);
            break;
        case FORWARD:
        case MULTI_FORWARD:
            int to_skip = start_forward(req, m, cmd, epollfd, infos);
            if (to_skip == 0) {
                fprintf(stderr, "Error: could not execute FORWARD\n");
                return -1;
            }
            req->curr_cmd = cmd;
            return 0;
        case REPLY:
            cw_log("Handling REPLY: req_id=%d\n", m->req_id);
            if (!reply(req, m, cmd)) {
                fprintf(stderr, "reply() failed\n");
                return -1;
            }
            // any further cmds[] for replied-to hop, not me
            return 1;
        case STORE:
        case LOAD:
            check(storage_path, "Error: Cannot execute LOAD/STORE cmd because no storage path has been defined");

            wrapper_t w;
            w.cmd = cmd;
            w.worker_id = infos->worker_id;
            w.req_id = req->req_id;

            if (write(infos->storefd, &w, sizeof(w)) < 0) {
                perror("storage worker write() failed");
                return -1;
            }

            req->curr_cmd = cmd_next(cmd);
            return 0;
        default:
            fprintf(stderr, "Error: Unknown cmd: %d\n", m->cmds[0].cmd);
            return 0;
        }
    }

    return 1;
}

int process_messages(req_info_t *req, int epollfd, thread_info_t *infos) {
    int executed = process_single_message(req, epollfd, infos);
    if (executed && conns[req->conn_id].serialize_request)
        return obtain_messages(req->conn_id, epollfd, infos);
    return executed;
}

int obtain_messages(int conn_id, int epollfd, thread_info_t* infos) {
    conn_info_t *conn = conn_get_by_id(conn_id);

    // batch processing of multiple messages, if received more than 1
    if (conn->serialize_request && conn->req_list != NULL)
        return 1;

    message_t *m = conn_recv_message(conn);
    while(m != NULL) {

        // FORWARD finished
        if (m->num == 0) {
            cw_log("Handling response to FORWARD from %s:%d, req_id=%d\n", inet_ntoa((struct in_addr) {conns[conn_id].target.sin_addr.s_addr}), 
                                                                           ntohs(conns[conn_id].target.sin_port), m->req_id);
            if (!handle_forward_reply(m->req_id, epollfd, infos)) {
                    cw_log("handle_forward_reply() failed\n");
                    return 0;
            }
        } else {
            req_info_t *req = conn_req_add(conn);
            req->message_ptr = (unsigned char*) m;
            req->curr_cmd = message_first_cmd(m);
            int executed = process_single_message(req, epollfd, infos);
            if (!executed && conns[conn_id].serialize_request) {
                conns[conn_id].curr_proc_buf += m->req_size;
                return 1;
            }
        }

        m = conn_recv_message(conn);
    };

    return 1;
}

int finalize_conn(int epollfd, int conn_id) {
    cw_log("finalize_conn() for conn %d\n", conn_id);
    int val;
    socklen_t len = sizeof(val);
    sys_check(getsockopt(conns[conn_id].sock, SOL_SOCKET, SO_ERROR, (void*)&val, &len));
    if (val != 0) {
        cw_log("getsockopt() reported connect() failure: %s\n", strerror(val));
        return 0;
    }
    // this may trigger send_messages() on return, if messages have already been enqueued
    conns[conn_id].status = READY;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = i2l(SOCKET, conn_id);
    sys_check(epoll_ctl(epollfd, EPOLL_CTL_MOD, conns[conn_id].sock, &ev));

    return 1;
}

void setnonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    assert(flags >= 0);
    flags |= O_NONBLOCK;
    assert(fcntl(fd, F_SETFL, flags) == 0);
}

void handle_timeout(int epollfd, thread_info_t *infos) {
    if (!pqueue_size(infos->timeout_queue))
        return;

    int req_id = pqueue_node_data(pqueue_top(infos->timeout_queue)).value;
    req_info_t *req = req_get_by_id(req_id);
    if (!req)
        return;

    message_t *m = req_get_message(req);
    conn_info_t *conn = conn_get_by_id(req->conn_id);

    remove_timeout(infos, req_id, epollfd);

    fwd_opts_t *fwd = cmd_get_opts(fwd_opts_t, req->curr_cmd);
    if (fwd->retries > 0) {
        cw_log("TIMEOUT expired, retry: %d\n", fwd->retries);
        
        fwd->retries--;
        process_messages(req, epollfd, infos);
    } else if (fwd->on_fail_skip > 0) {
        cw_log("TIMEOUT expired, failed, skipping: %d\n", fwd->on_fail_skip);
        
        req->curr_cmd = message_skip_cmds(m, req->curr_cmd, fwd->on_fail_skip);
        process_messages(req, epollfd, infos);
         conn_req_remove(conn, req);
    } else {
        cw_log("TIMEOUT expired, failed\n");
        conn_req_remove(conn, req);
    }
}

void exec_request(int epollfd, const struct epoll_event *p_ev, thread_info_t* infos) {
    int id;
    event_t type;
    l2i(p_ev->data.u64, (uint32_t*)&type, (uint32_t*) &id);
    
    cw_log("event_type=%s, id=%d\n", get_event_str(type), id);

    if (type == TIMER) {
        handle_timeout(epollfd, infos);
        return;
    }

    if ((type == SOCKET || type == CONNECT) && (conns[id].sock == -1 || conns[id].recv_buf == NULL))
            return;

    if (p_ev->events & EPOLLIN) {
        cw_log("calling recv_mesg()\n");
        if (!conn_recv(&conns[id]))
            goto err;
    }
    if ((p_ev->events & EPOLLOUT) && (type == CONNECT)) {
        cw_log("calling final_conn()\n");
        if (!finalize_conn(epollfd, id))
            goto err;
        // we need the send_messages() below to still be tried afterwards
    }
    if ((p_ev->events & EPOLLOUT) && (conns[id].curr_send_size > 0) && conns[id].status != CONNECTING && conns[id].status != NOT_INIT) {
        cw_log("calling send_mesg()\n");
        if (!conn_send(&conns[id]))
            goto err;
    }
    cw_log("conns[%d].status=%d (%s)\n", id, conns[id].status, conn_status_str(conns[id].status));
    
    // check whether we have new or leftover messages to process
    if (!obtain_messages(id, epollfd, infos))
        goto err;

    if (conns[id].curr_send_size > 0 && conns[id].status == READY) {
        struct epoll_event ev2;
        ev2.data.u64 = i2l(SOCKET, id);
        ev2.events = EPOLLIN | EPOLLOUT;
        cw_log("adding EPOLLOUT for sock=%d, conn_id=%d, curr_send_size=%lu\n",
               conns[id].sock, id, conns[id].curr_send_size);
        sys_check(epoll_ctl(epollfd, EPOLL_CTL_MOD, conns[id].sock, &ev2));
        conns[id].status = SENDING;
    }
    if (conns[id].curr_send_size == 0 && conns[id].status == SENDING) {
        struct epoll_event ev2;
        ev2.data.u64 = i2l(SOCKET, id);
        ev2.events = EPOLLIN;
        cw_log("removing EPOLLOUT for sock=%d, conn_id=%d, curr_send_size=%lu\n",
               conns[id].sock, id, conns[id].curr_send_size);
        sys_check(epoll_ctl(epollfd, EPOLL_CTL_MOD, conns[id].sock, &ev2));
        conns[id].status = READY;
    }

    return;

 err:
    close_and_forget(epollfd, conns[id].sock);
    conn_free(id);
}

void* storage_worker(void* args) {
    storage_info_t *infos = (storage_info_t *)args;

    int epollfd;
    struct epoll_event ev, events[MAX_EVENTS];

    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }
    
    // Add conn_worker(s) -> storage_worker communication pipe
    for (int i = 0; i < infos->nthread; i++) {
        ev.events = EPOLLIN;
        ev.data.u64 = i2l(infos->storefd[i], -1);
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->storefd[i], &ev) < 0)
            perror("epoll_ctl: storefd failed");
    }

    // Add termination handler
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = i2l(infos->terminationfd, -1);
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->terminationfd, &ev) < 0)
        perror("epoll_ctl: terminationfd failed");


    // Add periodic sync timerfd
    if (infos->periodic_sync_msec > 0) {
        if ((infos->tfd = timerfd_create(CLOCK_MONOTONIC, 0)) < 0) {
            perror("timerfd_create");
            exit(EXIT_FAILURE);
        }

        struct itimerspec ts;
        memset(&ts, 0, sizeof(ts));

        struct timespec ts_template;
        ts_template.tv_sec =  infos->periodic_sync_msec / 1000;
        ts_template.tv_nsec = (infos->periodic_sync_msec % 1000) * 1000000;

        //both interval and value have been set
        ts.it_value = ts_template;
        ts.it_interval = ts_template;

        if (timerfd_settime(infos->tfd, 0, &ts, NULL) < 0) {
            perror("timerfd_settime");
            exit(EXIT_FAILURE);
        }

        ev.events = EPOLLIN | EPOLLET;
        ev.data.u64 = i2l(infos->tfd, -1);
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->tfd, &ev) < 0)
            perror("epoll_ctl: terminationfd failed");
    }

    while (running) {
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");

            if (errno == EINTR) {
                running = 0;
                break;
            } else {
                perror("epoll_wait() failed: ");
                exit(EXIT_FAILURE);
            }
        }

        int fd;
        for (int i = 0; i < nfds; i++) {
            l2i(events[i].data.u64, (uint32_t*) &fd, NULL);

            if (fd == infos->terminationfd) {
                running = 0;
                break;
            }
            else if (fd == infos->tfd) {
                // NOTE: timerfd requires a read to be re-armed
                uint64_t val;
                if (read(infos->tfd, &val, sizeof(uint64_t)) < 0) {
                    perror("periodic sync read()");
                    running = 0;
                    break;
                }

                fsync(infos->storage_fd);

                // Too expensive??
                cw_log("storage sync...\n");
            }
            else {
                wrapper_t w;
                command_t *storage_cmd;
                int worker_id;
                int req_id;

                if (read(fd, &w, sizeof(w)) < 0) {
                    perror("storage worker read()");
                    running = 0;
                    break;
                }

                storage_cmd = w.cmd;
                worker_id = w.worker_id;
                req_id = w.req_id;

                cw_log("STORAGE cmd from conn_id %d\n", req_id);

                if (storage_cmd->cmd == STORE) {
                    store(infos, infos->store_buf, cmd_get_opts(store_opts_t, storage_cmd)->store_nbytes);
                }
                else if (storage_cmd->cmd == LOAD) {
                    size_t leftovers;
                    load(infos, infos->store_buf, cmd_get_opts(load_opts_t, storage_cmd)->load_nbytes, &leftovers);
                }
                else { // error
                    fprintf(stderr, "Unknown command sent to storage server - skipping");
                    continue;
                }

                safe_write(infos->store_replyfd[worker_id], (unsigned char*) &req_id, sizeof(req_id));
            }
        }
    }

    return (void*)1;
}

void* conn_worker(void* args) {
    thread_info_t *infos = (thread_info_t *)args;

    if (thread_affinity) {
        sys_check(aff_pin_to(infos->core_id));
        cw_log("thread %ld pinned to core %i\n", pthread_self(), infos->core_id);
    }

    int epollfd;
    struct epoll_event ev, events[MAX_EVENTS];

    sys_check(epollfd = epoll_create1(0));

    // Add listen socket
    int conn_id = conn_find_sock(infos->listen_sock);
    
    ev.events = EPOLLIN;

    if(conn_id == -1)
        ev.data.u64 = i2l(LISTEN, infos->listen_sock);
    else
        ev.data.u64 = i2l(SOCKET, conn_id);
    sys_check(epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->listen_sock, &ev) == -1);

    // Add termination fd
    ev.events = EPOLLIN;
    ev.data.u64 = i2l(TERMINATION, infos->terminationfd);
    sys_check(epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->terminationfd, &ev));

    // Add timer fd
    ev.events = EPOLLIN;
    ev.data.u64 = i2l(TIMER, infos->timerfd);
    sys_check(epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->timerfd, &ev));

    // Add storage reply fd
    if (storage_path) {
        ev.events = EPOLLIN;
        ev.data.u64 = i2l(STORAGE, infos->store_replyfd);
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->store_replyfd, &ev) < 0)
            perror("epoll_ctl: storefd failed");
    }

    while (running) {
        cw_log("epoll_wait()ing...\n");
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");

            if (errno == EINTR) {
                running = 0;
                break;
            } else {
                perror("epoll_wait() failed: ");
                exit(EXIT_FAILURE);
            }
        }

        int fd;
        event_t type;
        for (int i = 0; i < nfds; i++) {
            l2i(events[i].data.u64, &type, (uint32_t*) &fd);

            if (type == LISTEN) { // New connection
                struct sockaddr_in addr;
                socklen_t addr_size = sizeof(addr);
                int conn_sock;
                sys_check(conn_sock = accept(infos->listen_sock, (struct sockaddr *)&addr, &addr_size));

                cw_log("Accepted connection from: %s:%d\n",
                       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                setnonblocking(conn_sock);
                int val = 1;
                sys_check(setsockopt(conn_sock, IPPROTO_TCP, TCP_NODELAY,
                                     (void *)&val, sizeof(val)));

                int conn_id = conn_alloc(conn_sock, addr, TCP);
                if (conn_id < 0) {
                    fprintf(stderr, "Could not allocate new conn_info_t, closing...\n");
                    close_and_forget(epollfd, conn_sock);
                    continue;
                }

                conns[conn_id].status = READY;
                ev.events = EPOLLIN;
                ev.data.u64 = i2l(SOCKET, conn_id);

                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev) < 0)
                        perror("epoll_ctl() failed");
            }
            else if (type == STORAGE && storage_path && fd == infos->store_replyfd) {
                // storage operation completed
                // TODO: code

                int req_id_ACK;
                if (safe_read(infos->store_replyfd, (unsigned char*) &req_id_ACK, sizeof(req_id_ACK)) < 0) {
                    perror("storage worker read() failed");
                    continue;
                }

                cw_log("STORAGE ACK for req_id %d\n", req_id_ACK);
                process_messages(req_get_by_id(req_id_ACK), epollfd, infos);
                //exec_request(epollfd, &events[i], infos);
            } 
            else if (type == TERMINATION) {
                running = 0;
                break;
            }
            else {
                exec_request(epollfd, &events[i], infos);
            }
        }
    }

    return (void *)1;
}

int main(int argc, char *argv[]) {
    // Setup SIGINT signal handler
    signal(SIGINT, sigint_cleanup);

    cpu_set_t mask;
    struct sockaddr_in serverAddr;

    // Pipe comm
    int fds[MAX_THREADS][2];
    int fds2[MAX_THREADS][2];

    proto_t proto = TCP;

    // Storage info defaults
    storage_info.storage_fd = -1;
    storage_info.tfd = -1;
    storage_info.periodic_sync_msec = -1;
    storage_info.max_storage_size = MAX_STORAGE_SIZE;
    storage_info.storage_offset = 0; //TODO: mutual exclusion here to avoid race conditions in per-client thread mode
    storage_info.storage_eof = 0; //TODO: same here

    argc--;
    argv++;
    while (argc > 0) {
        if (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0) {
            printf(
                "Usage: dw_node [-h|--help] [-b bindname] [-tcp bindport] [-udp bindport]"
                "[-s|--storage path/to/storage/file] [--nt|--num-threads n] [--thread-affinity] "
                "[-m|--max-storage-size bytes] "
                "[--sync msec ]"
                "[--odirect]\n");
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[0], "-b") == 0) {
            assert(argc >= 2);
            bind_name = argv[1];
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-tcp") == 0 || strcmp(argv[0], "-udp") == 0) {
            assert(argc >= 2);
            proto = !strcmp(argv[0], "-tcp") ? TCP : UDP;
            bind_port = atol(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-nd") == 0 ||
                   strcmp(argv[0], "--no-delay") == 0) {  // not implemented
            assert(argc >= 2);
            no_delay = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-s") == 0 ||
                   strcmp(argv[0], "--storage") == 0) {
            assert(argc >= 2);
            storage_path = argv[1];
            argc--;
            argv++;
        } else if (strcmp(argv[0], "--sync") == 0) {
            assert(argc >= 2);
            storage_info.periodic_sync_msec = atoi(argv[1]);
            argc--;
            argv++; 
        } else if (strcmp(argv[0], "-m") == 0 ||
                   strcmp(argv[0], "--max-storage-size") == 0) {
            assert(argc >= 2);
            storage_info.max_storage_size = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-nt") == 0 || 
                   strcmp(argv[0], "--num-threads") == 0) {
            assert(argc >= 2);
            nthread = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "--odirect") == 0) {
            use_odirect = 1;
        } else if (strcmp(argv[0], "--thread-affinity") == 0) {
            thread_affinity = 1;

            if (argc >= 2 && argv[1][0] != '-') {
                thread_affinity_list = argv[1];
                argc--;
                argv++;
            }
        } else {
            fprintf(stderr, "Error: Unrecognized option: %s\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        argc--;
        argv++;
    }

    check(nthread > 0 && nthread <= MAX_THREADS, "--threads needs an argument between 1 and %d\n", MAX_THREADS);

    // Retrieve cpu set for thread-core pinning
    int core_it = 0;
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);

    cw_log("nproc=%ld (system capacity)\n", nproc);

    if (thread_affinity) {
        if (thread_affinity_list) {
            aff_list_parse(thread_affinity_list, &mask, nproc);
        }
        else {
            CPU_ZERO(&mask);
            sys_check(sched_getaffinity(0, sizeof(cpu_set_t), &mask));
        }

        // Point to first pinnable core
        core_it = aff_it_init(&mask, nproc);
    }

    conn_init();
    req_init();

    // Open storage file, if any
    if (storage_path) {
        int flags = O_RDWR | O_CREAT | O_TRUNC;
        if (use_odirect) flags |= O_DIRECT;
        sys_check(storage_info.storage_fd = open(storage_path, flags, S_IRUSR | S_IWUSR));
        struct stat s;
        sys_check(fstat(storage_info.storage_fd, &s));
        blk_size = s.st_blksize;
        cw_log("blk_size = %lu\n", blk_size);

        storage_info.terminationfd = eventfd(0, 0);
        storage_info.store_buf = malloc(BUF_SIZE);

        for (int i = 0; i < nthread; i++) {
            // conn_worker -> storage_worker
            if (pipe(fds[i]) == -1) {
               perror("pipe");
               exit(EXIT_FAILURE);
            }

            storage_info.storefd[i] = fds[i][0]; // read
            thread_infos[i].storefd = fds[i][1]; // write

            // storage_worker -> conn_worker
            if (pipe(fds2[i]) == -1) {
               perror("pipe");
               exit(EXIT_FAILURE);
            }

            storage_info.store_replyfd[i] = fds2[i][1]; // write 
            thread_infos[i].store_replyfd = fds2[i][0]; // read
        }

        storage_info.nthread = nthread;
    } else {
        for (int i = 0; i < nthread; i++) {
            thread_infos[i].storefd = -1;
            thread_infos[i].store_replyfd = -1;
        }
    }

    /*---- Configure settings of the server address struct ----*/
    /* Address family = Internet */
    serverAddr.sin_family = AF_INET;
    /* Set port number, using htons function to use proper byte order */
    serverAddr.sin_port = htons(bind_port);

    // Resolve hostname
    cw_log("Resolving %s...\n", bind_name);
    struct hostent *e = gethostbyname(bind_name);
    check(e != NULL);
    cw_log("Host %s resolved to %d bytes: %s\n", bind_name, e->h_length,
           inet_ntoa(*(struct in_addr *)e->h_addr));

    /* Set IP address */
    memmove((char *) &serverAddr.sin_addr.s_addr, (char *)e->h_addr, e->h_length);

    /* Set all bits of the padding field to 0 */
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    for (int i = 0; i < nthread; i++) {
        /*---- Create the socket(s). The three arguments are: ----*/
        /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this
        * case) */

        if (proto == TCP) {
            thread_infos[i].listen_sock = socket(PF_INET, SOCK_STREAM, 0);
        } else {
            thread_infos[i].listen_sock = socket(PF_INET, SOCK_DGRAM, 0);
            int conn_id = conn_alloc(thread_infos[i].listen_sock, serverAddr, UDP);
            conn_get_by_id(conn_id)->status = READY;
        }

        int val = 1;
        sys_check(setsockopt(thread_infos[i].listen_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(val)));
        sys_check(setsockopt(thread_infos[i].listen_sock, SOL_SOCKET, SO_REUSEPORT, (void *)&val, sizeof(val)));

        /*---- Bind the address struct to the socket ----*/
        sys_check(bind(thread_infos[i].listen_sock, (struct sockaddr *)&serverAddr,
                        sizeof(serverAddr)));

        cw_log("Node bound to %s:%d\n", inet_ntoa(serverAddr.sin_addr), bind_port);

        /*---- Listen on the socket, with 5 max connection requests queued ----*/
        if (proto == TCP)
            sys_check(listen(thread_infos[i].listen_sock, 5));
        cw_log("Accepting new connections...\n");

        thread_infos[i].terminationfd = eventfd(0, 0);
        thread_infos[i].timerfd =  timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK);
        thread_infos[i].timeout_queue = pqueue_alloc(MAX_REQS);

        // Round-robin thread-core pinning
        if (thread_affinity) {
            thread_infos[i].core_id = core_it;

            aff_it_next(&core_it, &mask, nproc);
        }

        thread_infos[i].worker_id = i;
    }

    // Init conns mutexs
    for (int i = 0; i < MAX_CONNS; i++) {
        sys_check(pthread_mutex_init(&conns[i].mtx, NULL));
    }

    // Init socks mutex
    // TODO: change sock_add and sock_dell's logic to avoid lock re-entrancy
    pthread_mutexattr_t attr;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    sys_check(pthread_mutex_init(&socks_mtx, &attr));

    // Init storage thread
    if (storage_path) {
        sys_check(pthread_create(&storer, NULL, storage_worker, (void *)&storage_info));
    }

    // Run
    if (nthread == 1) {
        conn_worker((void*) &thread_infos[0]);
    }
    else {
        
        // Init worker threads
        for (int i = 0; i < nthread; i++) {
            sys_check(pthread_create(&workers[i], NULL, conn_worker, (void *)&thread_infos[i]));
        }
    }

    // Clean-ups
    if (nthread > 1) {
        // Join worker threads
        for (int i = 0; i < nthread; i++) {
            sys_check(pthread_join(workers[i], NULL));
            close(thread_infos[i].terminationfd);
        }

        // Destroy conns mutexs
        for (int i = 0; i < MAX_CONNS; i++) {
            sys_check(pthread_mutex_destroy(&conns[i].mtx));
        }

        sys_check(pthread_mutex_destroy(&socks_mtx));
    }

    if (storage_path) {
        sys_check(pthread_join(storer, NULL));
        free(storage_info.store_buf);
    }

    // termination clean-ups
    if (storage_info.storage_fd >= 0) {
        close(storage_info.storage_fd);

        for (int i = 0; i < nthread; i++) {
            close(thread_infos[i].storefd);
            close(storage_info.storefd[i]);

            close(thread_infos[i].store_replyfd);
            close(storage_info.store_replyfd[i]);
        }
    }

    return 0;
}

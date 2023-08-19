#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h> /* See NOTES */
#include <unistd.h>

#include "cw_debug.h"
#include "message.h"
#include "timespec.h"

#define MAX_EVENTS 10

// I could be doing 0, 1, 2 or more of these at the same time => bitmask
typedef enum {
    RECEIVING = 1,      // receiving on bufs[].sock
    SENDING = 2,        // sending data for REPLY or FORWARD
    LOADING = 4,        // loading data from disk
    STORING = 8,        // storing data to disk
    CONNECTING = 16,    // waiting for connection establishment during a FORWARD
    FORWARDING = 32     // waiting for a FORWARD to complete
} req_status;

typedef struct {
    unsigned char *recv_buf;      // receive buffer, NULL for unused buf_info
    unsigned char *curr_recv_buf; // current pointer within receive buffer while RECEIVING
    unsigned long curr_recv_size; // leftover space in receive buffer

    unsigned char *curr_send_buf; // curr ptr in reply/fwd buffer while SENDING
    unsigned long curr_send_size; // size of leftover data to send
    unsigned long curr_send_sock; // sock we're sending to (reply vs forwarding)

    unsigned char *fwd_buf;       // forwarding buffer
    unsigned char *reply_buf;     // reply buffer
    unsigned char *store_buf;

    int sock;
    req_status status;
    int orig_sock_id;  // ID in socks[]
    pthread_mutex_t mtx;
} buf_info;

typedef struct {
    int listen_sock;

    int epollfd;
    struct epoll_event events[MAX_EVENTS];
    int terminationfd;  // special eventfd to handle termination
} thread_info_t;

#define MAX_BUFFERS 16

buf_info bufs[MAX_BUFFERS];

// used with --per-client-thread
#define MAX_THREADS 8
pthread_t workers[MAX_THREADS];
thread_info_t thread_infos[MAX_THREADS];

typedef struct {
    in_addr_t inaddr;  // target IP
    uint16_t port;     // target port (for multiple nodes on same host)
    int sock;  // socket handling messages from/to inaddr:port (-1 = unused)
} sock_info;

#define MAX_SOCKETS 16
sock_info socks[MAX_SOCKETS];
pthread_mutex_t socks_mtx;

char *bind_name = "0.0.0.0";
int bind_port = 7891;

int no_delay = 1;

int use_odirect = 0;
int nthread = 1;

// return index in socks[] of sock_info associated to inaddr:port, or -1 if not found
int sock_find_addr(in_addr_t inaddr, int port) {
    int rv = -1;
    if (nthread > 1)
        sys_check(pthread_mutex_lock(&socks_mtx));

    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (socks[i].sock != -1 && socks[i].inaddr == inaddr && socks[i].port == port) {
            rv = i;
            break;
        }
    }

    if (nthread > 1)
        sys_check(pthread_mutex_unlock(&socks_mtx));

    return rv;
}

// return index of sock in socks[]
int sock_find_sock(int sock) {
    assert(sock != -1);
    int rv = -1;

    if (nthread > 1)
        sys_check(pthread_mutex_lock(&socks_mtx));

    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (socks[i].sock == sock) {
            rv = i;
            break;
        }
    }

    if (nthread > 1)
        sys_check(pthread_mutex_unlock(&socks_mtx));

    return rv;
}

#define MAX_STORAGE_SIZE 1000000
char *storage_path = NULL;
int storage_fd = -1;
size_t max_storage_size = MAX_STORAGE_SIZE;
size_t storage_offset = 0; //TODO: mutual exclusion here to avoid race conditions in per-client thread mode
size_t storage_eof = 0; //TODO: same here

void sigint_cleanup(int _) {
    (void)_;  // to avoid unused var warnings

    // terminate workers by sending a notification
    // on their terminationfd
    if (nthread > 1) {
        for (int i = 0; i < nthread; i++) {
            eventfd_write(thread_infos[i].terminationfd, 1);
        }
    }
}

// add the IP/port into the socks[] map to allow FORWARD finding an
// already set-up socket, through sock_find()
// FIXME: bad complexity with many sockets
//
// return index of sock_info in socks[] where info has been added (or where it was already found),
//        or -1 if no unused entry were found in socks[]
int sock_add(in_addr_t inaddr, int port, int sock) {
    if (nthread > 1)
        sys_check(pthread_mutex_lock(&socks_mtx));

    int sock_id = sock_find_addr(inaddr, port);

    if (sock_id == -1) {
        for (int i = 0; i < MAX_SOCKETS; i++) {
            if (socks[i].sock == -1) {
                socks[i].inaddr = inaddr;
                socks[i].port = port;
                socks[i].sock = sock;
                sock_id = i;
                break;
            }
        }
    }

    if (nthread > 1)
        sys_check(pthread_mutex_unlock(&socks_mtx));
    return sock_id;
}

void sock_del_id(int id) {
    assert(id < MAX_SOCKETS);

    if (nthread > 1)
        sys_check(pthread_mutex_lock(&socks_mtx));

    cw_log("marking socks[%d] invalid\n", id);
    socks[id].sock = -1;

    if (nthread > 1)
        sys_check(pthread_mutex_unlock(&socks_mtx));
}

// make entry in socks[] associated to sock invalid, return entry ID if found or
// -1
int sock_del(int sock) {
    if (nthread > 1)
        sys_check(pthread_mutex_lock(&socks_mtx));

    int id = sock_find_sock(sock);

    if (id != -1)
        sock_del_id(id);

    if (nthread > 1)
        sys_check(pthread_mutex_unlock(&socks_mtx));

    return id;
}

// returns 1 if all bytes sent correctly, 0 if errors occurred
int send_all(int sock, unsigned char *buf, size_t len) {
    while (len > 0) {
        int sent;
        sent = send(sock, buf, len, MSG_NOSIGNAL);
        if (sent < 0) {
            perror("send() failed");
            return 0;
        }
        buf += sent;
        len -= sent;
    }
    return 1;
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

// return len, or -1 if an error occurred on read()
size_t recv_all(int sock, unsigned char *buf, size_t len) {
    size_t read_tot = 0;
    while (len > 0) {
        int read;
        read = recv(sock, buf, len, 0);
        if (read < 0)
            return -1;
        else if (read == 0)
            return read_tot;
        buf += read;
        len -= read;
        read_tot += read;
    }
    return read_tot;
}

int start_send(int buf_id, int sock, unsigned char *buf, size_t size);

// Copy req id from m into m_dst, and commands up to the matching REPLY (or the end of m),
// skipping the first cmd_id elems in m->cmds[].
//
// Return the number of copied commands
int copy_tail(message_t *m, message_t *m_dst, int cmd_id) {
    // copy message header
    m_dst->req_id = m->req_id;
    m_dst->req_size = 0;
    int nested_fwd = 0;
    // left-shift m->cmds[] into m_dst->cmds[], removing m->cmds[cmd_id]
    int i = cmd_id;

    for (; i < m->num; i++) {
        m_dst->cmds[i - cmd_id] = m->cmds[i];
        if (m->cmds[i].cmd == REPLY) {
            if (nested_fwd == 0)
                break;
            else
                nested_fwd--;
        } else if (m->cmds[i].cmd == FORWARD)
            nested_fwd++;
    }

    m_dst->num = i - cmd_id + 1;

    return m_dst->num;
}

// cmd_id is the index of the FORWARD item within m->cmds[] here, we
// remove the first (cmd_id+1) commands from cmds[], and forward the
// rest to the next hop
//
// returns number of forwarded commands as found in m, or 0 if a problem occurred
int forward(int buf_id, message_t *m, int cmd_id) {
    int sock_id = sock_find_addr(m->cmds[cmd_id].u.fwd.fwd_host,
                                 m->cmds[cmd_id].u.fwd.fwd_port);
    if (sock_id == -1) {
        int no_delay = 1;
        int clientSocket = socket(PF_INET, SOCK_STREAM, 0);
        sys_check(setsockopt(clientSocket, IPPROTO_TCP,
                             TCP_NODELAY, (void *)&no_delay,
                             sizeof(no_delay)));
        cw_log("connecting to: %s:%d\n", inet_ntoa((struct in_addr) {m->cmds[cmd_id].u.fwd.fwd_host}),
               ntohs(m->cmds[cmd_id].u.fwd.fwd_port));
        struct sockaddr_in addr;
        bzero((char *) &addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = m->cmds[cmd_id].u.fwd.fwd_host;
        addr.sin_port = m->cmds[cmd_id].u.fwd.fwd_port;
        sys_check(connect(clientSocket, &addr, sizeof(addr)));
        sock_id = sock_add(m->cmds[cmd_id].u.fwd.fwd_host, m->cmds[cmd_id].u.fwd.fwd_port, clientSocket);
    }
    int sock = socks[sock_id].sock;
    assert(sock != -1);
    message_t *m_dst = (message_t *)bufs[buf_id].fwd_buf;
    int forwarded = copy_tail(m, m_dst, cmd_id + 1);
    m_dst->req_size = m->cmds[cmd_id].u.fwd.pkt_size;

    cw_log("Forwarding req %u to %s:%d\n", m->req_id,
           inet_ntoa((struct in_addr){m->cmds[cmd_id].u.fwd.fwd_host}),
           ntohs(m->cmds[cmd_id].u.fwd.fwd_port));
#ifdef CW_DEBUG
    msg_log(m_dst, "  f: ");
#endif
    cw_log("  f: cmds[] has %d items, pkt_size is %u\n", m_dst->num,
           m_dst->req_size);

    // TODO: return to epoll loop to handle sending of long packets
    // (here I'm blocking the thread)
    if (!send_all(sock, bufs[buf_id].fwd_buf, m_dst->req_size))
        return 0;
    int fwd_reply_id = cmd_id + forwarded;
    cw_log("  f: cmd_id=%d, num=%d, fwd_repl_id=%d, forwarded=%d\n", cmd_id, m->num, fwd_reply_id, forwarded);
    check(fwd_reply_id < m->num && m->cmds[fwd_reply_id].cmd == REPLY);
    cw_log("  f: waiting for resp_size=%d bytes\n", m->cmds[fwd_reply_id].u.resp_size);
    if (!recv_all(sock, bufs[buf_id].reply_buf, m->cmds[fwd_reply_id].u.resp_size))
        return 0;
    return forwarded;
}

// returns 1 if reply sent correctly, 0 otherwise
int reply(int sock, int buf_id, message_t *m, int cmd_id) {
    message_t *m_dst = (message_t *)bufs[buf_id].reply_buf;

    m_dst->req_id = m->req_id;
    m_dst->req_size = m->cmds[cmd_id].u.resp_size;
    m_dst->num = 0;
    cw_log("Replying to req %u\n", m->req_id);
    cw_log("  cmds[] has %d items, pkt_size is %u\n", m_dst->num,
           m_dst->req_size);
#ifdef CW_DEBUG
    msg_log(m_dst, "  ");
#endif
    // TODO: return to epoll loop to handle sending of long packets
    // (here I'm blocking the thread)
    return start_send(buf_id, sock, bufs[buf_id].reply_buf, m_dst->req_size);
}

size_t recv_message(int sock, unsigned char *buf, size_t len) {
    assert(len >= 8);
    size_t read = recv_all(sock, buf, 8);
    if (read < 0)
        return -1;
    else if (read == 0)
        return read;
    message_t *m = (message_t *)buf;
    assert(len >= m->req_size - 8);
    read = recv_all(sock, buf + 8, m->req_size - 8);
    if (read < 0) return -1;
    assert(read == m->req_size - 8);
    return m->req_size;
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

void store(int buf_id, size_t bytes) {
    // generate the data to be stored
    if (use_odirect) bytes = (bytes + blk_size - 1) / blk_size * blk_size;
    cw_log("STORE: storing %lu bytes\n", bytes);

    //write, otherwise over-write
    if (storage_offset + bytes > max_storage_size) {
        lseek(storage_fd, 0, SEEK_SET);
        storage_offset = 0;
    }

    safe_write(storage_fd, bufs[buf_id].store_buf, bytes);

    storage_offset += bytes;

    fsync(storage_fd);

    if (storage_offset > storage_eof) {
        storage_eof = storage_offset;

        if (storage_eof > max_storage_size) {
            storage_eof = max_storage_size;
        }
    }
}

void load(int buf_id, size_t bytes, size_t* leftovers) {
    cw_log("LOAD: loading %lu bytes\n", bytes);

    if (storage_offset + bytes > storage_eof){
        lseek(storage_fd, 0, SEEK_SET);
        storage_offset = 0;
    }

    *leftovers = safe_read(storage_fd, bufs[buf_id].store_buf, bytes);
    storage_offset += bytes;
}

void close_and_forget(int epollfd, int sock) {
    cw_log("removing sock=%d from epollfd\n", sock);
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, sock, NULL) == -1)
        perror("epoll_ctl() failed while deleting socket");
    cw_log("removing sock=%d from socks[]\n", sock);
    sock_del(sock);
    close(sock);
}

int process_messages(int buf_id) {
    int sock = bufs[buf_id].sock;
    unsigned char *buf = bufs[buf_id].recv_buf;
    unsigned long msg_size = bufs[buf_id].curr_recv_buf - buf;

    // batch processing of multiple messages, if received more than 1
    do {
        cw_log("msg_size=%lu\n", msg_size);
        if (msg_size < sizeof(message_t)) {
            cw_log("Got incomplete header, need to recv() more...\n");
            break;
        }
        message_t *m = (message_t *)buf;
        cw_log("Received %lu bytes, req_id=%u, req_size=%u, num=%d\n", msg_size,
               m->req_id, m->req_size, m->num);
        if (msg_size < m->req_size) {
            cw_log(
                "Got header but incomplete message, need to recv() more...\n");
            break;
        }
        assert(m->req_size >= sizeof(message_t) && m->req_size <= BUF_SIZE);

#ifdef CW_DEBUG
        msg_log(m, "");
#endif

        for (int i = 0; i < m->num; i++) {
            if (m->cmds[i].cmd == COMPUTE) {
                compute_for(m->cmds[i].u.comp_time_us);
            } else if (m->cmds[i].cmd == FORWARD) {
                int to_skip = forward(buf_id, m, i);
                if (to_skip == 0) {
                    fprintf(stderr, "Error: could not execute FORWARD\n");
                    return 0;
                }
                // skip forwarded portion of cmds[]
                i += to_skip;
            } else if (m->cmds[i].cmd == REPLY) {
                if (!reply(sock, buf_id, m, i)) {
                    fprintf(stderr, "reply() failed\n");
                    return 0;
                }
                // any further cmds[] for replied-to hop, not me
                break;
            } else if (m->cmds[i].cmd == STORE) {
                if (!storage_path) {
                    fprintf(stderr, "Error: Cannot execute STORE cmd because no storage path has been defined\n");
                    exit(EXIT_FAILURE);
                }
                store(buf_id, m->cmds[i].u.store_nbytes);
            } else if (m->cmds[i].cmd == LOAD) {
                if (!storage_path) {
                    fprintf(stderr, "Error: Cannot execute LOAD cmd because no storage path has been defined\n");
                    exit(EXIT_FAILURE);
                }
                size_t leftovers;
                load(buf_id, m->cmds[i].u.load_nbytes, &leftovers);
            } else {
                fprintf(stderr, "Error: Unknown cmd: %d\n", m->cmds[0].cmd);
                return 0;
            }
        }

        // move to batch processing of next message if any
        buf += m->req_size;
        msg_size = bufs[buf_id].curr_recv_buf - buf;
        if (msg_size > 0)
            cw_log("Repeating loop with msg_size=%lu\n", msg_size);
    } while (msg_size > 0);

    if (buf == bufs[buf_id].curr_recv_buf) {
        // all received data was processed, reset curr_* for next receive
        bufs[buf_id].curr_recv_buf = bufs[buf_id].recv_buf;
        bufs[buf_id].curr_recv_size = BUF_SIZE;
    } else {
        // leftover received data, move it to beginning of buf unless already
        // there
        if (buf != bufs[buf_id].recv_buf) {
            // TODO do this only if we're beyond a threshold in buf[]
            unsigned long leftover = bufs[buf_id].curr_recv_buf - buf;
            cw_log(
                "Moving %lu leftover bytes back to beginning of buf with "
                "buf_id %d",
                leftover, buf_id);
            memmove(bufs[buf_id].recv_buf, buf, leftover);
            bufs[buf_id].curr_recv_buf = bufs[buf_id].recv_buf + leftover;
            bufs[buf_id].curr_recv_size = BUF_SIZE - leftover;
        }
    }

    return 1;
}

void buf_free(int buf_id) {
    cw_log("Freeing buf %d\n", buf_id);

    if (nthread > 1)
        sys_check(pthread_mutex_lock(&bufs[buf_id].mtx));

    free(bufs[buf_id].recv_buf);
    free(bufs[buf_id].reply_buf);
    free(bufs[buf_id].fwd_buf);
    free(bufs[buf_id].store_buf);

    bufs[buf_id].recv_buf = NULL;
    bufs[buf_id].reply_buf = NULL;

    if (nthread > 1)
        sys_check(pthread_mutex_unlock(&bufs[buf_id].mtx));
}

int buf_alloc(int conn_sock) {
    unsigned char *new_buf = NULL;
    unsigned char *new_reply_buf = NULL;
    unsigned char *new_fwd_buf = NULL;
    unsigned char *new_store_buf = NULL;

    new_buf = malloc(BUF_SIZE);
    new_reply_buf = malloc(BUF_SIZE);
    new_fwd_buf = malloc(BUF_SIZE);

    if (storage_path)
        new_store_buf =
            (use_odirect
             ? aligned_alloc(blk_size, BUF_SIZE + blk_size)
             : malloc(BUF_SIZE));

    if (new_buf == NULL || new_reply_buf == NULL || new_fwd_buf == NULL ||
        (storage_path && new_store_buf == NULL))
        goto continue_free;

    int buf_id;
    for (buf_id = 0; buf_id < MAX_BUFFERS; buf_id++) {
        if (nthread > 1)
            sys_check(pthread_mutex_lock(&bufs[buf_id].mtx));
        if (bufs[buf_id].recv_buf == 0) {
            break;  // unlock mutex above after mallocs
        }
        if (nthread > 1)
            sys_check(pthread_mutex_unlock(&bufs[buf_id].mtx));
    }
    if (buf_id == MAX_BUFFERS)
        goto continue_free;

    bufs[buf_id].recv_buf = new_buf;
    bufs[buf_id].reply_buf = new_reply_buf;
    bufs[buf_id].fwd_buf = new_fwd_buf;
    if (storage_path) bufs[buf_id].store_buf = new_store_buf;

    if (nthread > 1)
        sys_check(pthread_mutex_unlock(&bufs[buf_id].mtx));

    // From here, safe to assume that bufs[buf_id] is thread-safe
    cw_log("Connection assigned to worker %d\n", buf_id);
    bufs[buf_id].curr_recv_buf = bufs[buf_id].recv_buf;
    bufs[buf_id].curr_recv_size = BUF_SIZE;
    bufs[buf_id].curr_send_buf = NULL;
    bufs[buf_id].curr_send_size = 0;
    bufs[buf_id].sock = conn_sock;
    bufs[buf_id].status = RECEIVING;
    bufs[buf_id].orig_sock_id = -1;

    return buf_id;

 continue_free:

    if (new_buf) free(new_buf);
    if (new_reply_buf) free(new_reply_buf);
    if (new_fwd_buf) free(new_fwd_buf);
    if (storage_path && new_store_buf) free(new_store_buf);

    return -1;
}

int recv_messages(int buf_id) {
    int sock = bufs[buf_id].sock;
    size_t received =
        recv(sock, bufs[buf_id].curr_recv_buf, bufs[buf_id].curr_recv_size, 0);
    cw_log("recv() returned: %d\n", (int)received);
    if (received == 0) {
        cw_log("Connection closed by remote end\n");
        return 0;
    } else if (received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        cw_log("Got EAGAIN or EWOULDBLOCK, ignoring...\n");
        return 1;
    } else if (received == -1) {
        fprintf(stderr, "Unexpected error: %s\n", strerror(errno));
        return 0;
    }
    bufs[buf_id].curr_recv_buf += received;
    bufs[buf_id].curr_recv_size -= received;

    return 1;
}

// used during REPLYING or FORWARDING
int send_messages(int buf_id) {
    int sock = bufs[buf_id].curr_send_sock;
    cw_log("send_messages(): buf_id=%d, status=%d, sock=%d\n", buf_id, bufs[buf_id].status, sock);
    size_t sent =
        send(sock, bufs[buf_id].curr_send_buf, bufs[buf_id].curr_send_size, MSG_NOSIGNAL);
    cw_log("send() returned: %d\n", (int)sent);
    if (sent == 0) {
        // TODO: should not even be possible, ignoring
        cw_log("send() returned 0\n");
        return 1;
    } else if (sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        cw_log("Got EAGAIN or EWOULDBLOCK, ignoring...\n");
        return 1;
    } else if (sent == -1) {
        fprintf(stderr, "Unexpected error: %s\n", strerror(errno));
        bufs[buf_id].status &= ~SENDING;
        return 0;
    }
    bufs[buf_id].curr_send_buf += sent;
    bufs[buf_id].curr_send_size -= sent;
    if (bufs[buf_id].curr_send_size == 0) {
        bufs[buf_id].status &= ~SENDING;
        cw_log("send_messages(): buf_id=%d, status=%d\n", buf_id, bufs[buf_id].status);
    }

    return 1;
}

int start_send(int buf_id, int sock, unsigned char *buf, size_t size) {
    cw_log("buf_id: %d, status: %d\n", buf_id, bufs[buf_id].status);
    check(!(bufs[buf_id].status & SENDING));
    bufs[buf_id].status |= SENDING;
    cw_log("buf_id: %d, status: %d\n", buf_id, bufs[buf_id].status);
    bufs[buf_id].curr_send_buf = buf;
    bufs[buf_id].curr_send_size = size;
    bufs[buf_id].curr_send_sock = sock;
    return send_messages(buf_id);
}

int finalize_conn(int buf_id) {
    printf("finalize_conn()\n");
    return 1;
}

void setnonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    assert(flags >= 0);
    flags |= O_NONBLOCK;
    assert(fcntl(fd, F_SETFL, flags) == 0);
}

void exec_request(int epollfd, const struct epoll_event *p_ev) {
    int buf_id = p_ev->data.u32;
    if (bufs[buf_id].recv_buf == NULL)
        return;

    if ((p_ev->events | EPOLLIN) && (bufs[buf_id].status & RECEIVING)) {
        if (!recv_messages(buf_id))
            goto err;
    }
    if ((p_ev->events | EPOLLOUT) && (bufs[buf_id].status & SENDING)) {
        if (!send_messages(buf_id))
            goto err;
    }
    if ((p_ev->events | EPOLLOUT) && (bufs[buf_id].status & CONNECTING)) {
        if (finalize_conn(buf_id))
            goto err;
    }
    // check whether we have new or leftover messages to process
    if (!process_messages(buf_id))
        goto err;

    return;

 err:
    close_and_forget(epollfd, bufs[buf_id].sock);
    buf_free(buf_id);
}

void* epoll_main_loop(void* args) {
    thread_info_t *infos = (thread_info_t *)args;

    int epollfd;
    struct epoll_event ev, events[MAX_EVENTS];

    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }
    
    // Add listen socket
    ev.events = EPOLLIN;
    ev.data.fd = -1;  // Special value denoting listen_sock
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->listen_sock, &ev) == -1) {
        perror("epoll_ctl: listen_sock");
        exit(EXIT_FAILURE);
    }

    // Add termination fd
    ev.events = EPOLLIN;
    ev.data.fd = infos->terminationfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, infos->terminationfd, &ev) < 0)
        perror("epoll_ctl: terminationfd failed");

    int running = 1;
    while (running) {
        cw_log("epoll_wait()ing...\n");
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");

            if (errno == EINTR) {
                running = 0;
            } else {
                perror("epoll_wait() failed: ");
                exit(EXIT_FAILURE);
            }
        }

        printf("Ready conns: %d\n", nfds);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == -1) { // New connection
                struct sockaddr_in addr;
                socklen_t addr_size = sizeof(addr);
                int conn_sock =
                    accept(infos->listen_sock, (struct sockaddr *)&addr, &addr_size);

                if (conn_sock == -1) {
                    perror("accept() failed: ");
                    exit(EXIT_FAILURE);
                }

                cw_log("Accepted connection from: %s:%d\n",
                       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                // setnonblocking(conn_sock);
                int val = 1;
                sys_check(setsockopt(conn_sock, IPPROTO_TCP, TCP_NODELAY,
                                     (void *)&val, sizeof(val)));

                int buf_id = buf_alloc(conn_sock);
                if (buf_id < 0) {
                    fprintf(stderr, "Could not allocate new buf_info_t, closing...\n");
                    close_and_forget(epollfd, conn_sock);
                    continue;
                }

                ev.events = EPOLLIN | EPOLLOUT;
                // Use the data.u32 field to store the buf_id in bufs[]
                ev.data.u32 = buf_id;

                 if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev) < 0)
                        perror("epoll_ctl() failed");
            } 
            else if (events[i].data.fd == infos->terminationfd) {
                running = 0;
                break;
            }
            else {  // NOTE: unused if --per-client-thread
                exec_request(epollfd, &events[i]);
            }
        }
    }

    return (void *)1;
}

int main(int argc, char *argv[]) {
    // Setup SIGINT signal handler
    signal(SIGINT, sigint_cleanup);

    struct sockaddr_in serverAddr;

    argc--;
    argv++;
    while (argc > 0) {
        if (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0) {
            printf(
                "Usage: dw_node [-h|--help] [-b bindname] [-bp bindport] "
                "[-s|--storage path/to/storage/file] [--threads n] "
                "[-m|--max-storage-size bytes] "
                "[--odirect]\n");
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[0], "-b") == 0) {
            assert(argc >= 2);
            bind_name = argv[1];
            argc--;
            argv++;
        } else if (strcmp(argv[0], "-bp") == 0) {
            assert(argc >= 2);
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
        } else if (strcmp(argv[0], "-m") == 0 ||
                   strcmp(argv[0], "--max-storage-size") == 0) {
            assert(argc >= 2);
            max_storage_size = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "--threads") == 0) {
            assert(argc >= 2);
            nthread = atoi(argv[1]);
            argc--;
            argv++;
        } else if (strcmp(argv[0], "--odirect") == 0) {
            use_odirect = 1;
        } else {
            fprintf(stderr, "Error: Unrecognized option: %s\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        argc--;
        argv++;
    }

    assert(nthread > 0 && nthread <= MAX_THREADS);

    // Tag all buf_info as unused
    for (int i = 0; i < MAX_BUFFERS; i++) {
        bufs[i].recv_buf = 0;
    }

    // Tag all sock_info as unused
    for (int i = 0; i < MAX_SOCKETS; i++) {
        socks[i].sock = -1;
    }

    // Open storage file, if any
    if (storage_path) {
        int flags = O_RDWR | O_CREAT | O_TRUNC;
        if (use_odirect) flags |= O_DIRECT;
        sys_check(storage_fd = open(storage_path, flags, S_IRUSR | S_IWUSR));
        struct stat s;
        sys_check(fstat(storage_fd, &s));
        blk_size = s.st_blksize;
        cw_log("blk_size = %lu\n", blk_size);
    }

    /*---- Configure settings of the server address struct ----*/
    /* Address family = Internet */
    serverAddr.sin_family = AF_INET;
    /* Set port number, using htons function to use proper byte order */
    serverAddr.sin_port = htons(bind_port);
    /* Set IP address to localhost */
    serverAddr.sin_addr.s_addr = inet_addr(bind_name);
    /* Set all bits of the padding field to 0 */
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    /*---- Create the socket. The three arguments are: ----*/
    /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this
     * case) */
    for (int i = 0; i < nthread; i++) {
        thread_infos[i].listen_sock = socket(PF_INET, SOCK_STREAM, 0);

        int val = 1;
        sys_check(setsockopt(thread_infos[i].listen_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(val)));
        sys_check(setsockopt(thread_infos[i].listen_sock, SOL_SOCKET, SO_REUSEPORT, (void *)&val, sizeof(val)));

        /*---- Bind the address struct to the socket ----*/
        sys_check(bind(thread_infos[i].listen_sock, (struct sockaddr *)&serverAddr,
                        sizeof(serverAddr)));

        cw_log("Node binded to %s:%d\n", bind_name, bind_port);

        /*---- Listen on the socket, with 5 max connection requests queued ----*/
        sys_check(listen(thread_infos[i].listen_sock, 5));
        cw_log("Accepting new connections...\n");

        thread_infos[i].terminationfd = eventfd(0, 0);

    }

    if (nthread == 1) {
        epoll_main_loop((void*) &thread_infos[0]);
    }
    else {
        // Init worker threads
        for (int i = 0; i < nthread; i++) {
            sys_check(pthread_create(&workers[i], NULL, epoll_main_loop,
                                     (void *)&thread_infos[i]));
        }

        // Init bufs mutexs
        for (int i = 0; i < MAX_BUFFERS; i++) {
            sys_check(pthread_mutex_init(&bufs[i].mtx, NULL));
        }

        // Init socks mutex
        // TODO: change sock_add and sock_dell's logic to avoid lock re-entrancy
        pthread_mutexattr_t attr;

        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

        sys_check(pthread_mutex_init(&socks_mtx, &attr));
    }

    // Clean-ups
    if (nthread > 1) {
        // Join worker threads
        for (int i = 0; i < nthread; i++) {
            sys_check(pthread_join(workers[i], NULL));
            close(thread_infos[i].terminationfd);
        }

        // Destroy bufs mutexs
        for (int i = 0; i < MAX_BUFFERS; i++) {
            sys_check(pthread_mutex_destroy(&bufs[i].mtx));
        }

        sys_check(pthread_mutex_destroy(&socks_mtx));
    }

    // termination clean-ups
    if (storage_fd >= 0) {
        close(storage_fd);
    }

    return 0;
}

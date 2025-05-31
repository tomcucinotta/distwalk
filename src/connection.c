#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "connection.h"
#include "dw_debug.h"

conn_info_t conns[MAX_CONNS];

// helper function to run SSL handshake in a non-blocking way
// returns 1 if handshake is complete, 0 if handshake is in progress, -1 if an error occured
int conn_do_ssl_handshake(int conn_id) {
    conn_info_t *conn = &conns[conn_id];

    if (conn->status != SSL_HANDSHAKE)
        return 1; // nothing to do

    int ret = conn->ssl_is_server ? SSL_accept(conn->ssl) : SSL_connect(conn->ssl);
    if (ret <= 0) {
        int err = SSL_get_error(conn->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            dw_log("SSL handshake in progress on conn_id=%d (WANT_READ/WRITE)\n", conn_id);
            return 0;  // handshake still in progress
        }
        dw_log("SSL handshake error on conn_id=%d: %d\n", conn_id, err);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    dw_log("SSL handshake complete on conn_id=%d\n", conn_id);
    conn->ssl_handshake_done = 1;
    conn->status = READY;
    return 1;
}

const char *conn_status_str(conn_status_t s) {
    static const char *status_str[STATUS_NUMBER] = {
        "NOT INIT",
        "READY",
        "SENDING",
        "CONNECTING",
        "SSL HANDSHAKE",
        "CLOSE",
    };
    return status_str[s];
}

void conn_init() {
    for (int i = 0; i < MAX_CONNS; i++) {
        conns[i].recv_buf = NULL;
        conns[i].send_buf = NULL;
        conns[i].sock = -1;
        conns[i].busy = 0;
        conns[i].use_ssl = 0;
        conns[i].ssl = NULL;
        conns[i].ssl_handshake_done = 0;
        conns[i].ssl_is_server = 0;
        pthread_mutex_init(&conns[i].ssl_mtx, NULL);
    }
}



conn_status_t conn_set_status(conn_info_t* conn, conn_status_t status) {
    conn_status_t prev = conn->status;
    conn->status = status;

    return prev;
}

conn_status_t conn_set_status_by_id(int conn_id, conn_status_t status) {
    return conn_set_status(conn_get_by_id(conn_id), status);
}

conn_status_t conn_get_status(conn_info_t* conn) {
    return conn->status;
}

conn_status_t conn_get_status_by_id(int conn_id) {
    return conn_get_status(conn_get_by_id(conn_id));
}

conn_info_t* conn_get_by_id(int conn_id) {
    return &conns[conn_id];
}

int conn_get_id_by_ptr(conn_info_t * conn) {
    return conn - &conns[0];
}

req_info_t* conn_req_add(conn_info_t *conn) {
    req_info_t *req = req_alloc();
    if (req == NULL)
        return NULL;

    req->conn_id = conn_get_id_by_ptr(conn);
    req->target = conn->target;
    req->next = conn->req_list;
    if (req->next)
        req->next->prev = req;
    conn->req_list = req;

    dw_log("REQUEST create req_id:%d, conn_id: %d\n", req->req_id, conn_get_id_by_ptr(conn));
    return req;
}

static void conn_reset(conn_info_t *conn) {
    for (int i = 0; i < MAX_CONNS; i++)
        for (req_info_t *temp = conns[i].req_list; temp != NULL; temp = temp->next) {
            dw_log("conn_reset(%d): conn: %d, req_id: %d, .conn_id: %d -> ",
                   conn_get_id_by_ptr(conn), i, temp->req_id, temp->conn_id);
            if (temp->message_ptr) {
#ifdef DW_DEBUG
                msg_log(req_get_message(temp), "");
#endif
            } else
                dw_log("\n");
        }
    for (req_info_t *temp = conn->req_list; temp != NULL; temp = req_unlink(temp)) {
        dw_log("conn_reset(): freeing req_id: %d, conn_id: %d, .conn_id: %d -> ",
               temp->req_id, conn_get_id_by_ptr(conn), temp->conn_id);
        if (temp->message_ptr) {
#ifdef DW_DEBUG
            msg_log(req_get_message(temp), "");
#endif
        } else
            dw_log("\n");
    }
}

req_info_t* conn_req_remove(conn_info_t *conn, req_info_t *req) {
    if (conn->enable_defrag) {
        unsigned long req_size = req_get_message(req)->req_size;
        unsigned long leftover = conn->curr_recv_buf - (req->message_ptr + req_size);
    
        memmove(req->message_ptr, req->message_ptr + req_size, leftover);
        dw_log("DEFRAGMENT remove req_id:%d, conn_id:%d [%p, %p[\n", req->req_id, req->conn_id, 
                                                                 req->message_ptr, req->message_ptr + req_size);

        conn->curr_recv_buf -= req_size;
        conn->curr_recv_size += req_size;
        assert(conn->curr_proc_buf >= req->message_ptr + req_size);
        conn->curr_proc_buf -= req_size;

        for (req_info_t *temp = req->prev; temp != NULL; temp = temp->prev) {
            dw_log("DEFRAGMENT update ptr, req_id:%d message [%p, %p[ -> [%p, %p[\n", 
               temp->req_id,
               temp->message_ptr,
               temp->message_ptr + req_get_message(temp)->req_size,
               temp->message_ptr - req_size,
               temp->message_ptr - req_size + req_get_message(temp)->req_size);
            assert(temp->message_ptr >= req->message_ptr + req_size);
            temp->message_ptr -= req_size;
        }
    }

    if (conn->req_list == req)
        conn->req_list = conn->req_list->next;
    return req_unlink(req);
}

// return index in conns[] of conn_info_t associated to inaddr:port, or -1 if not found
int conn_find_existing(struct sockaddr_in target, proto_t proto) {
    int rv = -1;
    //if (nthread > 1)
    //    sys_check(pthread_mutex_lock(&socks_mtx));

    pthread_t curr_thread = pthread_self();
    for (int i = 0; i < MAX_CONNS; i++) {
        if (conns[i].sock == -1)
            continue;
        if (proto == UDP && conns[i].parent_thread == curr_thread) {
            rv = i;
            break;
        } else if (proto == TCP && conns[i].target.sin_port == target.sin_port && conns[i].target.sin_addr.s_addr == target.sin_addr.s_addr && conns[i].proto == proto) {
            rv = i;
            break;
        }
    }

    //if (nthread > 1)
    //    sys_check(pthread_mutex_unlock(&socks_mtx));

    return rv;
}

// return index of in conns[] of conn_info_t associated to sock, or -1 if not found
int conn_find_sock(int sock) {
    assert(sock != -1);
    int rv = -1;

    //if (nthread > 1) sys_check(pthread_mutex_lock(&socks_mtx));

    for (int i = 0; i < MAX_CONNS; i++) {
        if (conns[i].sock == sock) {
            rv = i;
            break;
        }
    }

    //if (nthread > 1) sys_check(pthread_mutex_unlock(&socks_mtx));

    return rv;
}

void conn_del_id(int id) {
    assert(id >= 0 && id < MAX_CONNS);

    //if (nthread > 1) sys_check(pthread_mutex_lock(&socks_mtx));

    dw_log("marking conns[%d] invalid\n", id);
    conn_reset(&conns[id]);
    conns[id].sock = -1;

    //if (nthread > 1) sys_check(pthread_mutex_unlock(&socks_mtx));
}

// make entry in conns[] associated to sock invalid, return entry ID if found or -1
int conn_del_sock(int sock) {
    //if (nthread > 1) sys_check(pthread_mutex_lock(&socks_mtx));

    int id = conn_find_sock(sock);

    if (id != -1)
        conn_del_id(id);

    //if (nthread > 1) sys_check(pthread_mutex_unlock(&socks_mtx));

    return id;
}

void conn_free(int conn_id) {
    if (conn_id < 0)
        return;
    dw_log("Freeing conn %d\n", conn_id);

    conn_reset(&conns[conn_id]);
    free(conns[conn_id].recv_buf);   
    conns[conn_id].recv_buf = NULL;
    free(conns[conn_id].send_buf);   
    conns[conn_id].send_buf = NULL;

    // clean up SSL if used
    if (conns[conn_id].use_ssl) {
        SSL_shutdown(conns[conn_id].ssl);
        SSL_free(conns[conn_id].ssl);
        conns[conn_id].ssl = NULL;
    }

    conns[conn_id].status = CLOSE;
    conns[conn_id].sock = -1;
    atomic_store(&conns[conn_id].busy, 0);

    // reset handshake state for this connection
    conns[conn_id].ssl_handshake_done = 0;
    conns[conn_id].ssl_is_server = 0;
}

int conn_alloc(int conn_sock, struct sockaddr_in target, proto_t proto) {
    int conn_id;
    for (conn_id = 0; conn_id < MAX_CONNS; conn_id++)
        if (atomic_exchange(&conns[conn_id].busy, 1) == 0)
            break;

    if (conn_id == MAX_CONNS)
        return -1;

    // From here, safe to assume that conns[conn_id] is thread-safe
    unsigned char *new_recv_buf = NULL;
    unsigned char *new_send_buf = NULL;

    new_recv_buf = calloc(BUF_SIZE, sizeof(unsigned char));
    new_send_buf = calloc(BUF_SIZE, sizeof(unsigned char));

    if (!new_recv_buf || !new_send_buf)
        goto continue_free;

    conns[conn_id].proto = proto;
    conns[conn_id].target = target;
    conns[conn_id].sock = conn_sock;
    conns[conn_id].status = (proto == TCP ? NOT_INIT : READY);
    conns[conn_id].recv_buf = new_recv_buf;
    conns[conn_id].send_buf = new_send_buf;
    conns[conn_id].parent_thread = pthread_self(); 
    conns[conn_id].use_ssl = 0;
    conns[conn_id].ssl = NULL;
    conns[conn_id].ssl_handshake_done = 0;
    conns[conn_id].ssl_is_server = 0;

    dw_log("CONN allocated, conn_id: %d\n", conn_id);
    conns[conn_id].curr_recv_buf = conns[conn_id].recv_buf;
    conns[conn_id].curr_proc_buf = conns[conn_id].recv_buf;
    conns[conn_id].curr_recv_size = BUF_SIZE;
    conns[conn_id].curr_send_buf = conns[conn_id].send_buf;
    conns[conn_id].curr_send_size = 0;
    conns[conn_id].serialize_request = 0;
    
    ((message_t*) conns[conn_id].send_buf)->cmds[0].cmd = EOM;
    ((message_t*) conns[conn_id].recv_buf)->cmds[0].cmd = EOM;

    return conn_id;

 continue_free:

    if (new_recv_buf)
        free(new_recv_buf);
    if (new_send_buf)
        free(new_send_buf);

    return -1;
}

unsigned char *get_send_buf(conn_info_t *pc, size_t size) {
    assert(pc->curr_send_buf - pc->send_buf + pc->curr_send_size + size <= BUF_SIZE);
    return pc->curr_send_buf + pc->curr_send_size;
}

message_t* conn_prepare_send_message(conn_info_t *conn) {
    message_t* m = (message_t*) (conn->send_buf + conn->curr_send_size);
    m->req_size = BUF_SIZE - (conn->curr_send_buf - conn->send_buf + conn->curr_send_size);
    return m;
}

message_t* conn_prepare_recv_message(conn_info_t *conn) {
    dw_log("Check whether we have new or leftover messages to process...\n");
    unsigned long msg_size = conn->curr_recv_buf - conn->curr_proc_buf;
    message_t *m = (message_t *)conn->curr_proc_buf;

    if (msg_size < sizeof(message_t)) {
        dw_log("Got incomplete header [recv size:%lu, header size:%lu], need to recv() more...\n", msg_size, sizeof(message_t));
        return NULL;
    }

    if (msg_size < m->req_size) {
        dw_log("Got header but incomplete message [recv size:%lu, expected size:%d], need to recv() more...\n", msg_size, m->req_size);
        return NULL;
    }
    assert(m->req_size >= sizeof(message_t) && m->req_size <= BUF_SIZE);

    dw_log("Got complete ");
#ifdef DW_DEBUG
    msg_log(m, "");
#endif

    conn->curr_proc_buf += m->req_size;
    return m;
}

// start sending a message, assume the head of the curr_send_buffer is a message_t type
// returns the number of bytes sent, -1 if an error occured
int conn_start_send(conn_info_t *conn, struct sockaddr_in target) {
    message_t *m = (message_t*) (conn->send_buf + conn->curr_send_size);
    conn->target = target;
    dw_log("SEND starting, conn_id: %d, status: %s, msg_size: %d\n", conn_get_id_by_ptr(conn), conn_status_str(conn->status), m->req_size);
    if (conn->curr_send_size == 0)
        conn->curr_send_buf = conn->send_buf;
    // move end of send operation forward by size bytes
    conn->curr_send_size += m->req_size;

    if (conn->status == CONNECTING || conn->status == SSL_HANDSHAKE || conn->status == NOT_INIT)
        return 0;
    else
        return conn_send(conn);
}

// wrapper for SSL write that first attempts the handshake in a non-blocking way
static int conn_ssl_send(conn_info_t *conn) {
    pthread_mutex_lock(&conn->ssl_mtx);

    ssize_t sent = SSL_write(conn->ssl, conn->curr_send_buf, conn->curr_send_size);
    dw_log("SEND (SSL) conn_id=%d, curr_send_size=%lu\n", conn_get_id_by_ptr(conn), conn->curr_send_size);
    if (sent <= 0) {
        int err = SSL_get_error(conn->ssl, sent);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            dw_log("SSL_write() got WANT_{WRITE,READ}, ignoring...\n");
            pthread_mutex_unlock(&conn->ssl_mtx);
            return 0;
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            dw_log("SSL connection closed by peer\n");
            conn->status = CLOSE;
            pthread_mutex_unlock(&conn->ssl_mtx);
            return 0;
        }
        fprintf(stderr, "SSL_write() error: %d\n", err);
        ERR_print_errors_fp(stderr);
        pthread_mutex_unlock(&conn->ssl_mtx);
        return -1;
    }
    dw_log("SEND (SSL) returned: %d\n", (int)sent);

    conn->curr_send_buf += sent;
    conn->curr_send_size -= sent;
    if (conn->curr_send_size == 0)
        conn->curr_send_buf = conn->send_buf;

    pthread_mutex_unlock(&conn->ssl_mtx);
    return (int)sent;
}

// wrapper for SSL read that first attempts the handshake in a non-blocking way
static int conn_ssl_recv(conn_info_t *conn) {
    pthread_mutex_lock(&conn->ssl_mtx);

    if (conn->status == SSL_HANDSHAKE) {
        dw_log("Cannot receive: SSL handshake in progress on conn_id=%d\n", conn_get_id_by_ptr(conn));
        pthread_mutex_unlock(&conn->ssl_mtx);
        return 1;
    }

    ssize_t received = SSL_read(conn->ssl, conn->curr_recv_buf, conn->curr_recv_size);
    dw_log("RECV (SSL) returned: %d\n", (int)received);
    if (received == 0) {
        dw_log("SSL_read() connection closed by remote end\n");
        pthread_mutex_unlock(&conn->ssl_mtx);
        return 0;
    } else if (received < 0) {
        int err = SSL_get_error(conn->ssl, received);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            dw_log("SSL_read() got WANT_{READ,WRITE}, ignoring...\n");
            pthread_mutex_unlock(&conn->ssl_mtx);
            return -1;
        }
        fprintf(stderr, "SSL_read() error: %d\n", err);
        ERR_print_errors_fp(stderr);
        pthread_mutex_unlock(&conn->ssl_mtx);
        return 0;
    }
    conn->curr_recv_buf += received;
    conn->curr_recv_size -= received;
    pthread_mutex_unlock(&conn->ssl_mtx);
    return 1;
}

int conn_send(conn_info_t *conn) {
    int sock = conn->sock;
    dw_log("SEND conn_id=%d, status=%d (%s), curr_send_size=%lu, sock=%d\n", conn_get_id_by_ptr(conn), conn->status, conn_status_str(conn->status), conn->curr_send_size, sock);

    if (conn->use_ssl)
        return conn_ssl_send(conn);

    ssize_t sent = sendto(sock, conn->curr_send_buf, conn->curr_send_size, MSG_NOSIGNAL, (const struct sockaddr*)&conn->target, sizeof(conn->target));
    if (sent == 0) {
        // TODO: should not even be possible, ignoring
        dw_log("SEND returned 0\n");
        return 0;
    }

    if (sent == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            dw_log("SEND Got EAGAIN or EWOULDBLOCK, ignoring...\n");
            return 0;
        } 

        if (errno == EPIPE || errno == ECONNRESET) {
            dw_log("SEND Connection closed by remote end conn_id=%d\n", conn_get_id_by_ptr(conn));
            conn->status = CLOSE;
            return 0;
        }

        fprintf(stderr, "SEND Unexpected error: %s\n", strerror(errno));
        return -1;
    }
    dw_log("SEND returned: %d\n", (int)sent);

    conn->curr_send_buf += sent;
    conn->curr_send_size -= sent;
    if (conn->curr_send_size == 0)
        conn->curr_send_buf = conn->send_buf;

    return (int)sent;
}

// return 1 if received succesfully, -1 on EAGAIN or EWOULDBLOCK, and 0 on other errors
int conn_recv(conn_info_t *conn) {
    int sock = conn->sock;
    socklen_t recvsize = sizeof(conn->target);

    if (conn->use_ssl)
        return conn_ssl_recv(conn);

    ssize_t received = recvfrom(sock, conn->curr_recv_buf, conn->curr_recv_size, 0,
                               (struct sockaddr*)&conn->target, (socklen_t*)&recvsize);
    dw_log("RECV returned: %d\n", (int)received);
    if (received == 0) {
        dw_log("RECV connection closed by remote end\n");
        return 0;
    } else if (received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        dw_log("RECV Got EAGAIN or EWOULDBLOCK, ignoring...\n");
        return -1;
    } else if (received == -1) {
        fprintf(stderr, "RECV Unexpected error: %s\n", strerror(errno));
        return 0;
    }
    conn->curr_recv_buf += received;
    conn->curr_recv_size -= received;

    return 1;
}

int conn_enable_ssl(int conn_id, SSL_CTX *ctx, int is_server) {
    if (conn_id < 0 || conn_id >= MAX_CONNS)
        return -1;

    conn_info_t *conn = &conns[conn_id];
    if (conn->sock < 0) {
        dw_log("conn_enable_ssl(): invalid socket\n");
        return -1;
    }
    if (conn->use_ssl) {
        dw_log("conn_enable_ssl(): SSL is already enabled\n");
        return 0; // already enabled
    }

    conn->ssl = SSL_new(ctx);
    if (!conn->ssl) {
        fprintf(stderr, "SSL_new() failed\n");
        return -1;
    }
    if (!SSL_set_fd(conn->ssl, conn->sock)) {
        fprintf(stderr, "SSL_set_fd() failed\n");
        SSL_free(conn->ssl);
        conn->ssl = NULL;
        return -1;
    }
    if (is_server)
        SSL_set_accept_state(conn->ssl);
    else
        SSL_set_connect_state(conn->ssl);

    conn->use_ssl = 1;
    conn->ssl_handshake_done = 0;
    conn->ssl_is_server = is_server;
    conn->status = SSL_HANDSHAKE;
    dw_log("SSL enabled on conn_id=%d; handshake pending (state set to SSL_HANDSHAKE)\n", conn_id);
    return 1;
}

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "connection.h"
#include "cw_debug.h"

conn_info_t conns[MAX_CONNS];


const char *conn_status_str(int s) {
    static const char *ready = "READY", *connecting = "CONNECTING", *sending = "SENDING", *not_init = "NOT INIT";
    const char *ret;
    if (s == READY)
        ret = ready;
    if (s == CONNECTING)
        ret = connecting;
    if (s == SENDING)
        ret = sending;
    if (s == NOT_INIT)
        ret = not_init;
    return ret;
}

void conn_init() {
	for (int i = 0; i < MAX_CONNS; i++) {
        conns[i].sock = -1;
        conns[i].recv_buf = NULL;
        conns[i].send_buf = NULL;
    }
}

conn_info_t* conn_get_by_id(int conn_id) {
	return &conns[conn_id];
}

req_info_t* conn_req_add(conn_info_t *conn) {
	req_info_t *req = req_alloc();

	req->conn_id = conn->conn_id;
    req->target = conn->target;
	req->next = conn->req_list;
	if (req->next)
		req->next->prev = req;
	conn->req_list = req;

	cw_log("REQUEST create req_id:%d, conn_id: %d", req->req_id, conn->conn_id);
	return req;
}

static void conn_reset(conn_info_t *conn) {
	for (req_info_t *temp = conn->req_list; temp != NULL; temp = req_free(temp)){};
}

req_info_t* conn_req_remove(conn_info_t *conn, req_info_t *req) {


	unsigned long req_size = req_get_message(req)->req_size;
    unsigned long leftover = conn->curr_recv_buf - (req->message_ptr + req_size);
    memmove(req->message_ptr, req->message_ptr + req_size, leftover);

    cw_log("DEFRAGMENT remove, conn_id:%d empty memory [%p, %p[\n", req->conn_id, req->message_ptr, req->message_ptr + req_size);

    req->message_ptr = NULL;
    conn->curr_recv_buf -= req_size;
    conn->curr_proc_buf -= req_size;
    conn->curr_recv_size += req_size;
    for (req_info_t *temp = req->prev; temp != NULL; temp = temp->prev) {
        cw_log("DEFRAGMENT update ptr, req_id:%d message [%p, %p[ -> [%p, %p[\n", 
            temp->req_id,
            temp->message_ptr,
            temp->message_ptr + req_get_message(temp)->req_size,
            temp->message_ptr - req_size,
            temp->message_ptr - req_size + req_get_message(temp)->req_size);
        temp->message_ptr -= req_size;
    }

    if (conn->req_list == req)
		conn->req_list = conn->req_list->next;
	return req_free(req);
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
    assert(id < MAX_CONNS);

    //if (nthread > 1) sys_check(pthread_mutex_lock(&socks_mtx));

    cw_log("marking conns[%d] invalid\n", id);
    conns[id].sock = -1;
    conn_reset(&conns[id]);

    //if (nthread > 1) sys_check(pthread_mutex_unlock(&socks_mtx));
}

// make entry in conns[] associated to sock invalid, return entry ID if found or -1
int conn_del_sock(int sock) {
    //if (nthread > 1) sys_check(pthread_mutex_lock(&socks_mtx));

    int id = conn_find_sock(sock);

    if (id != -1){
        conn_del_id(id);
    }

    //if (nthread > 1) sys_check(pthread_mutex_unlock(&socks_mtx));

    return id;
}

void conn_free(int conn_id) {
    cw_log("Freeing conn %d\n", conn_id);

    //if (nthread > 1) sys_check(pthread_mutex_lock(&conns[conn_id].mtx));

    conn_reset(&conns[conn_id]);
    free(conns[conn_id].recv_buf);   conns[conn_id].recv_buf = NULL;
    free(conns[conn_id].send_buf);   conns[conn_id].send_buf = NULL;
    conns[conn_id].sock = -1;

    //if (nthread > 1) sys_check(pthread_mutex_unlock(&conns[conn_id].mtx));
}

int conn_alloc(int conn_sock, struct sockaddr_in target, proto_t proto) {
    unsigned char *new_recv_buf = NULL;
    unsigned char *new_send_buf = NULL;

    new_recv_buf = malloc(BUF_SIZE);
    new_send_buf = malloc(BUF_SIZE);

    if (new_recv_buf == NULL || new_send_buf == NULL)
        goto continue_free;

    int conn_id;
    for (conn_id = 0; conn_id < MAX_CONNS; conn_id++) {
        //if (nthread > 1) sys_check(pthread_mutex_lock(&conns[conn_id].mtx));
        if (conns[conn_id].sock == -1) {
            break;  // unlock mutex above after mallocs
        }
        //if (nthread > 1) sys_check(pthread_mutex_unlock(&conns[conn_id].mtx));
    }
    if (conn_id == MAX_CONNS)
        goto continue_free;

    conns[conn_id].conn_id = conn_id;
    conns[conn_id].proto = proto;
    conns[conn_id].target = target;
    conns[conn_id].sock = conn_sock;
    conns[conn_id].status = (proto == TCP ? NOT_INIT : READY);
    conns[conn_id].recv_buf = new_recv_buf;
    conns[conn_id].send_buf = new_send_buf;
    conns[conn_id].parent_thread = pthread_self(); 
    //if (nthread > 1) sys_check(pthread_mutex_unlock(&conns[conn_id].mtx));

    // From here, safe to assume that conns[conn_id] is thread-safe
    cw_log("CONN allocated, conn_id: %d\n", conn_id);
    conns[conn_id].curr_recv_buf = conns[conn_id].recv_buf;
    conns[conn_id].curr_proc_buf = conns[conn_id].recv_buf;
    conns[conn_id].curr_recv_size = BUF_SIZE;
    conns[conn_id].curr_send_buf = conns[conn_id].send_buf;
    conns[conn_id].curr_send_size = 0;
    conns[conn_id].serialize_request = 0;

    //if (nthread > 1) sys_check(pthread_mutex_unlock(&conns[conn_id].mtx));

    return conn_id;

 continue_free:

    if (new_recv_buf) free(new_recv_buf);
    if (new_send_buf) free(new_send_buf);

    return -1;
}

unsigned char *get_send_buf(conn_info_t *pc, size_t size) {
    assert(pc->curr_send_buf - pc->send_buf + pc->curr_send_size + size <= BUF_SIZE);
    return pc->curr_send_buf + pc->curr_send_size;
}

message_t* conn_send_message(conn_info_t *conn) {
	message_t* m = (message_t*) conn->send_buf + conn->curr_send_size;
	m->req_size = BUF_SIZE - (conn->curr_send_buf - conn->send_buf + conn->curr_send_size);
	return m;
}

message_t* conn_recv_message(conn_info_t *conn) {
	unsigned long msg_size = conn->curr_recv_buf - conn->curr_proc_buf;
	message_t *m = (message_t *)conn->curr_proc_buf;;

	if (msg_size < sizeof(message_t)) {
            cw_log("Got incomplete header [recv size:%lu, header size:%lu], need to recv() more...\n", msg_size, sizeof(message_t));
            return NULL;
        }
        
        if (msg_size < m->req_size) {
            cw_log("Got header but incomplete message [recv size:%lu, expected size:%d], need to recv() more...\n", msg_size, m->req_size);
            return NULL;
        }
        assert(m->req_size >= sizeof(message_t) && m->req_size <= BUF_SIZE);

        cw_log("Got complete ");
#ifdef CW_DEBUG
        msg_log(m, "");
#endif

    conn->curr_proc_buf += m->req_size;
    return m;
}

// start sending a message, assume the head of the curr_send_buffer is a message_t type
// returns the number of bytes sent, -1 if an error occured
int conn_start_send(conn_info_t *conn, struct sockaddr_in target) {
	message_t *m = (message_t*) conn->send_buf + conn->curr_send_size;
    conn->target = target;
	cw_log("SEND starting, conn_id: %d, status: %s, msg_size: %d\n", conn->conn_id, conn_status_str(conn->status), m->req_size);
    if (conn->curr_send_size == 0)
        conn->curr_send_buf = conn->send_buf;
    // move end of send operation forward by size bytes
    conn->curr_send_size += m->req_size;

    if (conn->status == CONNECTING || conn->status == NOT_INIT)
        return 0;
    else
        return conn_send(conn);
}

int conn_send(conn_info_t *conn) {
	int sock = conn->sock;
    cw_log("SEND conn_id=%d, status=%d (%s), curr_send_size=%lu, sock=%d\n", conn->conn_id, conn->status, conn_status_str(conn->status), conn->curr_send_size, sock);
    size_t sent = sendto(sock, conn->curr_send_buf, conn->curr_send_size, MSG_NOSIGNAL, (const struct sockaddr*)&conn->target, sizeof(conn->target));
    if (sent == 0) {
        // TODO: should not even be possible, ignoring
        cw_log("SEND returned 0\n");
        return 0;
    } else if (sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        cw_log("SEND Got EAGAIN or EWOULDBLOCK, ignoring...\n");
        return 0;
    } else if (sent == -1) {
        fprintf(stderr, "SEND Unexpected error: %s\n", strerror(errno));
        return -1;
    }
    cw_log("SEND returned: %d\n", (int)sent);

    conn->curr_send_buf += sent;
    conn->curr_send_size -= sent;
    if (conn->curr_send_size == 0) {
        conn->curr_send_buf = conn->send_buf;
    }

    return sent;
}

int conn_recv(conn_info_t *conn) {
    int sock = conn->sock;
    socklen_t recvsize = sizeof(conn->target);
    size_t received =
        recvfrom(sock, conn->curr_recv_buf, conn->curr_recv_size, 0, (struct sockaddr*)&conn->target, (socklen_t*)&recvsize);
    cw_log("RECV returned: %d\n", (int)received);
    if (received == 0) {
        cw_log("RECV connection closed by remote end\n");
        return 0;
    } else if (received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        cw_log("RECV Got EAGAIN or EWOULDBLOCK, ignoring...\n");
        return 1;
    } else if (received == -1) {
        fprintf(stderr, "RECV Unexpected error: %s\n", strerror(errno));
        return 0;
    }
    conn->curr_recv_buf += received;
    conn->curr_recv_size -= received;

    return 1;
}

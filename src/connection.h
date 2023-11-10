#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include "message.h"
#include "request.h"

#ifndef MAX_CONNS
	#define MAX_CONNS 16
#endif

typedef enum {
    NOT_INIT,
    READY,
    SENDING,
    CONNECTING,           
} conn_status;

typedef struct {
	int conn_id;
    proto_t proto;                // transport protocol to use (TCP or UDP)
    int sock;                     // -1 for unused conn_info_t
    conn_status status;           // status of the connection

    struct sockaddr_in target;    // target of the connection

    unsigned char *recv_buf;      // receive buffer
    unsigned char *send_buf;      // send buffer

    unsigned char *curr_recv_buf; // current pointer within receive buffer while receiving
    unsigned long curr_recv_size; // leftover space in receive buffer

    unsigned char *curr_proc_buf; // current message within receive buffer being processed

    unsigned char *curr_send_buf; // curr ptr in send buffer while SENDING
    unsigned long curr_send_size; // size of leftover data to send

    req_info_t *req_list;
    unsigned int serialize_request;
    pthread_t parent_thread;
    pthread_mutex_t mtx;
} conn_info_t;

extern conn_info_t conns[MAX_CONNS];

const char *conn_status_str(int s);

void conn_init();

int conn_alloc(int sock, struct sockaddr_in target, proto_t proto);
void conn_free(int conn_id);

conn_info_t* conn_get_by_id(int conn_id);
req_info_t* conn_req_add(conn_info_t *conn);
req_info_t* conn_req_remove(conn_info_t *conn, req_info_t *req);

unsigned char *get_send_buf(conn_info_t *pc, size_t size);

message_t* conn_send_message(conn_info_t *conn);
message_t* conn_recv_message(conn_info_t *conn);
void conn_remove_message(conn_info_t *conn);

int conn_find_existing(struct sockaddr_in target, proto_t proto);
int conn_find_sock(int sock);
void conn_del_id(int id);
int conn_del_sock(int sock);

int conn_start_send(conn_info_t *conn, struct sockaddr_in target);
int conn_send(conn_info_t *conn);
int conn_recv(conn_info_t *conn);

#endif
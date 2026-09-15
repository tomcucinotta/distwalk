#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <stdint.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include "message.h"
#include "request.h"

#ifdef DPDK_ENABLED
#include "dw_dpdk.h"
#endif

#define MAX_CONNS 8192

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif

#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif
#define ZC_TRACKING_SIZE 256


typedef enum {
    NOT_INIT,
    READY,
    SENDING,
    CONNECTING,    // used with TCP only
    SSL_HANDSHAKE, // used with SSL only
    CLOSE,
    STATUS_NUMBER  // keep this as last
} conn_status_t;

typedef struct {
    uint32_t send_id;   // ID associated with one successful MSG_ZEROCOPY send
    size_t size;        // number of bytes sent with this ID
    int confirmed;      // 1 when the kernel notification for this ID was received
} zc_send_tracking_t;

typedef struct {
    proto_t proto;                // transport protocol to use (TCP or UDP)
    int sock;                     // -1 for unused conn_info_t
    conn_status_t status;         // status of the connection

    struct sockaddr_in target;    // target of the connection

    unsigned char *recv_buf;      // receive buffer
    unsigned char *send_buf;      // send buffer

    unsigned char *curr_recv_buf; // current pointer within receive buffer while receiving
    unsigned long curr_recv_size; // leftover space in receive buffer

    unsigned char *curr_proc_buf; // current message within receive buffer being processed

    unsigned char *curr_send_buf; // curr ptr in send buffer while SENDING
    unsigned long curr_send_size; // size of leftover data to send

        // --- Added for sendfile() support ----
    int     file_fd;              // storage file fd for sendfile
    off_t file_offset;            // current offset in the file for sendfile
    size_t  file_remaining;       // remaining bytes to send from the file
    reply_mode_t reply_mode;       // whether to use SENDFILE for REPLYs on this connection

    req_info_t *req_list;        // request ring buffer
    unsigned int serialize_request;
    pthread_t parent_thread;
    atomic_int busy;             // 1 if conn is allocated, 0 otherwise
    
    int enable_defrag;            // Defragment receive buffer to reduce memory usage

#ifdef DPDK_ENABLED
    struct rte_mbuf *rx_mbufs[RX_BURST_SIZE];
    struct rte_mbuf *tx_mbufs[TX_BURST_SIZE];
    uint16_t tx_count;
#endif

    // SSL/TLS support
    int use_ssl;                  // 1 if SSL is enabled for this connection
    SSL *ssl;                     // OpenSSL handle for this connection
    int ssl_handshake_done;       // 1 if handshake is complete
    int ssl_is_server;            // 1 if server side, 0 if client
    pthread_mutex_t ssl_mtx;      // protects non-blocking handshake

    // Zero-copy support
    int use_zc;                   // 1 if zero-copy is enabled for this connection

    zc_send_tracking_t zc_tracking[ZC_TRACKING_SIZE]; // tracking for zero-copy sends
    size_t zc_tracking_count;    // number of zero-copy sends stored in the tracking array
    size_t zc_release_index;        // index of the next zero-copy send to release (not yet released)

    uint32_t zc_next_id;          // ID for the next MSG_ZEROCOPY send
} conn_info_t;

extern conn_info_t conns[MAX_CONNS];

const char *conn_status_str(conn_status_t s);

void conn_init();
int conn_enable_zc(conn_info_t *conn);
int conn_alloc(int sock, struct sockaddr_in target, proto_t proto);
void conn_free(int conn_id);

conn_status_t conn_get_status(conn_info_t* conn);
conn_status_t conn_get_status_by_id(int conn_id);
conn_status_t conn_set_status(conn_info_t* conn, conn_status_t status);
conn_status_t conn_set_status_by_id(int conn_id, conn_status_t status);

conn_info_t* conn_get_by_id(int conn_id);
int conn_get_id_by_ptr(conn_info_t * conn);

req_info_t* conn_req_add(conn_info_t *conn);
req_info_t* conn_req_remove(conn_info_t *conn, req_info_t *req);

unsigned char *get_send_buf(conn_info_t *pc, size_t size);

// req_size field of returned message is initialized with the available space in send buffer
message_t* conn_prepare_send_message(conn_info_t *conn);
/* retrieve next received message in conn's recv buffer */
message_t* conn_prepare_recv_message(conn_info_t *conn);
void conn_remove_message(conn_info_t *conn);

int conn_find_existing(struct sockaddr_in target, proto_t proto);
int conn_find_sock(int sock);
void conn_del_id(int id);
int conn_del_sock(int sock);

int conn_start_send(conn_info_t *conn, struct sockaddr_in target);
int conn_start_sendfile(conn_info_t *conn, struct sockaddr_in target, int fd_sendfile, off_t sendfile_offset, size_t sendfile_size);
int conn_send(conn_info_t *conn);
int conn_send_v2(conn_info_t *conn);
int conn_recv(conn_info_t *conn);
int conn_flush(conn_info_t *conn);
int conn_read_zc_notifications(conn_info_t *conn);

int conn_enable_ssl(int conn_id, SSL_CTX *ctx, int is_server);
int conn_do_ssl_handshake(int conn_id);

#endif /* __CONNECTION_H__ */

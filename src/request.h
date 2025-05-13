#ifndef __REQUEST_H__
#define __REQUEST_H__

#include "message.h"
#include "priority_queue.h"

#include <stdatomic.h>

#define MAX_REQS (1u << 16)


typedef struct req_info_t req_info_t;

struct req_info_t {
    int req_id;
    int conn_id;
    struct sockaddr_in target;
    int fwd_replies_left;
    int fwd_replies_mask;
    int fwd_retries;
    int fwd_timeout;
    int fwd_on_fail_skip;
    unsigned char *message_ptr;
    command_t *curr_cmd;
    node_t *timeout_node;
    req_info_t *prev, *next;
};

extern req_info_t reqs[MAX_REQS];
extern atomic_int last_reqs;

void req_init();

req_info_t* req_alloc();
req_info_t* req_unlink(req_info_t *r);

static inline message_t* req_get_message(req_info_t *r) {
    return (message_t*)r->message_ptr;
}

static inline req_info_t *req_get_by_id(int req_id) {
    if (reqs[req_id % MAX_REQS].req_id != req_id)
        return NULL;
    return &reqs[req_id % MAX_REQS];
}

#endif /* __REQUEST_H__ */

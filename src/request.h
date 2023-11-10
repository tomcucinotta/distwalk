#ifndef REQUEST_H
#define REQUEST_H

#include "message.h"
#include "priority_queue.h"

#define MAX_REQS (1u << 16)


typedef struct req_info_t req_info_t;

struct req_info_t{
    int req_id;
    int conn_id;
    struct sockaddr_in target;

    int fwd_replies_left;

    unsigned char *message_ptr;
    
    int curr_cmd_id;

    pqueue_node_t *timeout_node;
    req_info_t *prev, *next;
};

extern req_info_t reqs[MAX_REQS];
extern int last_reqs;

void req_init();

message_t* req_get_message(req_info_t *r);

req_info_t* req_alloc();
req_info_t* req_free(req_info_t *r);

req_info_t *req_get_by_id(int req_id);

#endif
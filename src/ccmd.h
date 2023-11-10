#ifndef __CCMD_H__
#define __CMD__H__

#include "message.h"
#include "distrib.h"

/*
    Hybrid queue-stack
    - FIFO for "action" commands (i.e., COMPUTE, STORE, LOAD, FORWARD)
    - LIFO for reply commands, except last one

    Custom-built for creating command chains in a message struct
*/

typedef struct ccmd_node_t {
    command_type_t cmd;
    pd_spec_t pd_val;
    fwd_opts_t fwd;
    reply_opts_t resp;
    int n_skip;
    struct ccmd_node_t* next;
} ccmd_node_t;

typedef struct ccmd_queue_t {
    uint8_t num;
    uint8_t last_reply_called;

    ccmd_node_t* head_actions;
    ccmd_node_t* tail_actions;

    ccmd_node_t* head_replies;
    ccmd_node_t* tail_replies;
} ccmd_t;

void ccmd_init(ccmd_t** q);
ccmd_node_t *ccmd_add(ccmd_t* q, command_type_t cmd, pd_spec_t *p_pd_spec);
void ccmd_attach_last_reply(ccmd_t* q, pd_spec_t *p_pd_spec);
int ccmd_dump(ccmd_t* q, message_t* m);
void ccmd_destroy(ccmd_t* q);
void ccmd_log(ccmd_t* q);

static inline ccmd_node_t *ccmd_last_action(ccmd_t *q) { return q->tail_actions; }
static inline ccmd_node_t *ccmd_last_reply(ccmd_t *q) { return q->tail_replies; }
#endif /* __CMD_H__ */

/** @file */

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
    pd_spec_t pd_val2;
    store_opts_t store;
    load_opts_t load;
    fwd_opts_t fwd;
    reply_opts_t resp;
    int n_skip;
    struct ccmd_node_t* next;
} ccmd_node_t;

typedef struct ccmd_queue_t {
    uint8_t num;
    uint8_t last_reply;

    ccmd_node_t* head;
    ccmd_node_t* tail;
} ccmd_t;

/**
 * @brief Initialize ccmd queue
 * 
 * @param q pointer to ccmd_t* queue to be initialized
 */
void ccmd_init(ccmd_t** q);
ccmd_node_t *ccmd_add(ccmd_t* q, command_type_t cmd, pd_spec_t *p_pd_spec);
ccmd_node_t *ccmd_skip(ccmd_node_t *curr, int n);
int ccmd_dump(ccmd_t* q, message_t* m);
void ccmd_destroy(ccmd_t** q);
void ccmd_log(ccmd_t* q);

static inline ccmd_node_t *ccmd_last(ccmd_t *q) { return q->tail; }
#endif /* __CMD_H__ */

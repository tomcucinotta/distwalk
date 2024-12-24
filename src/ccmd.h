/** @file */

#ifndef __CCMD_H__
#define __CMD__H__

#include "queue.h"
#include "message.h"
#include "distrib.h"
/*
    queue.h wrapper to handle the creation of the chain of commands (specified via cmdline)
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

void ccmd_add(queue_t* q, command_type_t cmd, pd_spec_t *p_pd_spec);
ccmd_node_t *ccmd_skip(ccmd_node_t *curr, int n);
int ccmd_dump(queue_t* q, message_t* m);
void ccmd_destroy(queue_t** q);
void ccmd_log(queue_t* q);

static inline ccmd_node_t *ccmd_first(queue_t* q) { return (!q->size) ? NULL : (ccmd_node_t*) queue_node_data(queue_head(q)).ptr; }
static inline ccmd_node_t *ccmd_last(queue_t* q) { return (!q->size) ? NULL : (ccmd_node_t*) queue_node_data(queue_tail(q)).ptr; }

#endif /* __CMD_H__ */

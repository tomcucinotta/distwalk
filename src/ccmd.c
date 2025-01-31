#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "queue.h"
#include "ccmd.h"
#include "message.h"
#include "dw_debug.h"

void ccmd_add(queue_t* q, command_type_t cmd, pd_spec_t *p_pd_spec) {
    if (!q) {
        printf("ccmd_add() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    ccmd_node_t* new_node = calloc(1, sizeof(ccmd_node_t));
    new_node->cmd = cmd;
    new_node->pd_val = *p_pd_spec;

    if (queue_size(q) >= 1)
        ccmd_last(q)->next = new_node;

    data_t data = { .ptr=new_node };
    queue_enqueue(q, cmd, data);
}

extern __thread struct drand48_data rnd_buf;

ccmd_node_t* ccmd_skip(ccmd_node_t* node, int to_skip) {
    int skipped = to_skip;
    ccmd_node_t *itr = node;

    while (itr && skipped > 0) {
        int nested_fwd = 0;
        do {
            if (itr->cmd == FORWARD_BEGIN)
                nested_fwd++;
            else if (itr->cmd == FORWARD_CONTINUE) {
                while (itr->next->cmd == FORWARD_CONTINUE)
                    itr = itr->next;
            } else if (itr->cmd == REPLY)
                nested_fwd--;
            itr = itr->next;
        } while (itr && nested_fwd > 0);
        skipped--;
    }

    return itr;
}

// returns 1 if the message has been succesfully copied, 0 if there is not enough space (saved in req_size field)
int ccmd_dump(queue_t* q, message_t* m) {
    check(q, "ccmd_dump() error - Initialize queue first");
    check(m, "ccmd_dump() error - NullPointer message_t*");

    ccmd_node_t* ccmd_itr = queue_node_data(queue_head(q)).ptr;

    double x = 0;
    command_t *m_cmd_itr = message_first_cmd(m);

    while (ccmd_itr) {
        m_cmd_itr->cmd = ccmd_itr->cmd;

        if(m->req_size < cmd_type_size(ccmd_itr->cmd))
            return -1;
        m->req_size -= cmd_type_size(ccmd_itr->cmd);

        switch (ccmd_itr->cmd) {
            case STORE:
                *cmd_get_opts(store_opts_t, m_cmd_itr) = ccmd_itr->store;
                cmd_get_opts(store_opts_t, m_cmd_itr)->offset = pd_sample(&ccmd_itr->pd_val2);
                cmd_get_opts(store_opts_t, m_cmd_itr)->store_nbytes = pd_sample(&ccmd_itr->pd_val);
                break;
            case COMPUTE:
                cmd_get_opts(comp_opts_t, m_cmd_itr)->comp_time_us = pd_sample(&ccmd_itr->pd_val);
                break;
            case LOAD:
                *cmd_get_opts(load_opts_t, m_cmd_itr) = ccmd_itr->load;
                cmd_get_opts(load_opts_t, m_cmd_itr)->offset = pd_sample(&ccmd_itr->pd_val2);
                cmd_get_opts(load_opts_t, m_cmd_itr)->load_nbytes = pd_sample(&ccmd_itr->pd_val);
                break;
            case REPLY: 
                *cmd_get_opts(reply_opts_t, m_cmd_itr) = ccmd_itr->resp;
                cmd_get_opts(reply_opts_t, m_cmd_itr)->resp_size = pd_sample(&ccmd_itr->pd_val);
                break;
            case PSKIP:
                drand48_r(&rnd_buf, &x);
                dw_log("skip: x=%g, prob=%g\n", x, ccmd_itr->pd_val.val);
                if (x <= ccmd_itr->pd_val.val)
                    ccmd_itr = ccmd_skip(ccmd_itr->next, ccmd_itr->n_skip);
                else
                    ccmd_itr = ccmd_itr -> next;
                continue;
            case FORWARD_BEGIN:
            case FORWARD_CONTINUE:
                *cmd_get_opts(fwd_opts_t, m_cmd_itr) = ccmd_itr->fwd;
                cmd_get_opts(fwd_opts_t, m_cmd_itr)->pkt_size = pd_sample(&ccmd_itr->pd_val);
                break;
            default: 
                fprintf(stderr, "ccmd_dump() - Unknown command type\n");
                exit(EXIT_FAILURE);
        }
        m_cmd_itr = cmd_next(m_cmd_itr);
        //printf("%s\n", get_command_name(curr->cmd));
        ccmd_itr = ccmd_itr->next;
    }
    if(m->req_size < cmd_type_size(EOM))
            return -1;
    m->req_size -= cmd_type_size(EOM);
    m_cmd_itr->cmd = EOM;

    return 1;
}

void ccmd_destroy(queue_t** q) {
    check(*q, "ccmd_destroy() error - Initialize queue first");

    ccmd_node_t* curr = ccmd_first(*q);
    ccmd_node_t* tmp = NULL;
    
    while (curr) {
        tmp = curr->next;
        free(curr);
        curr = tmp;
    }

    queue_drop(*q);
    queue_free(*q);
    *q = NULL;
}

void ccmd_log(queue_t* q) {
    check(q, "ccmd_log() error - Initialize queue first");

    int itr = queue_itr_begin(q);
    while (queue_itr_has_next(q, itr)) {
        node_t* node = queue_itr_next(q, &itr);
        ccmd_node_t* curr = (ccmd_node_t*) queue_node_data(node).ptr;
        char opts[128] = "";

        switch (curr->cmd) {
            case STORE:
                sprintf(opts, "%sb,%s,offset=%s", pd_str(&curr->pd_val),
                        curr->store.wait_sync ? "sync" : "nosync", pd_str(&curr->pd_val2));
                break;
            case COMPUTE:
                sprintf(opts, "%sus", pd_str(&curr->pd_val));
                break;
            case LOAD:
                sprintf(opts, "%sb,offset=%s", pd_str(&curr->pd_val),
                        pd_str(&curr->pd_val2));
                break;
            case PSKIP:
                if (curr->pd_val.val < 1.0)
                    sprintf(opts, "%d,prob=%s", curr->n_skip, pd_str(&curr->pd_val));
                else
                    sprintf(opts, "%d", curr->n_skip);
                break;
            case FORWARD_BEGIN:
            case FORWARD_CONTINUE:
                sprintf(opts, "%s://%s:%d,%sb,retries=%d,timeout=%d,branched=%d,nack=%d", curr->fwd.proto == TCP ? "tcp" : "udp", 
                                                                                  inet_ntoa((struct in_addr) {curr->fwd.fwd_host}), ntohs(curr->fwd.fwd_port), 
                                                                                  pd_str(&curr->pd_val), curr->fwd.retries, curr->fwd.timeout, curr->fwd.branched,
                                                                                  curr->fwd.n_ack);
                break;
            case REPLY:
                sprintf(opts, "%sb", pd_str(&curr->pd_val));
                break;
            default: 
                fprintf(stderr, "ccmd_log() - Unknown command type\n");
                exit(EXIT_FAILURE);
        }
        printf("%s(%s)%s", get_command_name(curr->cmd), opts, queue_itr_has_next(q, itr) ? "->" : "");
    }
    printf("\n");
}

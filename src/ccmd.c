#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "ccmd.h"
#include "message.h"
#include "dw_debug.h"

void ccmd_init(ccmd_t** q) {
    *q = malloc(sizeof(ccmd_t));

    (*q)->num = 0;
    (*q)->last_reply = 0;

    (*q)->head = NULL;
    (*q)->tail = NULL;
}

ccmd_node_t *ccmd_add(ccmd_t* q, command_type_t cmd, pd_spec_t *p_pd_spec) {
    if (!q) {
        printf("ccmd_add() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    ccmd_node_t* new_node = calloc(1, sizeof(ccmd_node_t));
    new_node->cmd = cmd;
    new_node->pd_val = *p_pd_spec;

    if (!q->head) {
        q->head = new_node;
        q->tail = q->head;
    } else {
        q->tail->next = new_node;
        q->tail = q->tail->next;
    }
    
    q->num++;
    return new_node;
}

extern __thread struct drand48_data rnd_buf;

ccmd_node_t* ccmd_skip(ccmd_node_t* node, int to_skip) {
    int skipped = to_skip;
    ccmd_node_t *itr = node;

    while (itr && skipped > 0) {
        int nested_fwd = 0;

        do {
            if (itr->cmd == FORWARD)
                nested_fwd++;
            else if (itr->cmd == MULTI_FORWARD) {
                nested_fwd++;
                while (itr->next->cmd == MULTI_FORWARD)
                    itr = itr->next;
            } else if (itr->cmd == REPLY)
                nested_fwd--;
            itr = itr->next;
        } while (itr && nested_fwd > 0);

        skipped--;
    }

    return itr;
}

/* ccmd_node_t *ccmd_skip(ccmd_node_t *curr, int n) {
    int prev_was_mfwd = 0;
    while (n-- > 0 && curr) {
        if (curr->cmd == FORWARD || (curr->cmd == MULTI_FORWARD && !prev_was_mfwd)) {
            int nested_fwd = 0;
            do {
                check(curr != NULL);
                prev_was_mfwd = (curr->cmd == MULTI_FORWARD);
                curr = curr->next;
                if (curr->cmd == REPLY) {
                    if (nested_fwd == 0)
                        break;
                    else
                        nested_fwd--;
                } else if (curr->cmd == FORWARD || (curr->cmd == MULTI_FORWARD && !prev_was_mfwd))
                    nested_fwd++;
            } while (curr->cmd != REPLY && nested_fwd != 0);
        }

        if (curr) {
            prev_was_mfwd = (curr->cmd == MULTI_FORWARD);
            curr = curr->next;
        }
    }

    return curr;
}*/

// returns 1 if the message has been succesfully copied, 0 if there is not enough space (saved in req_size field)
int ccmd_dump(ccmd_t* q, message_t* m) {
    check(q, "ccmd_dump() error - Initialize queue first");
    check(m, "ccmd_dump() error - NullPointer message_t*");

    ccmd_node_t* ccmd_itr = q->head;

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
            case MULTI_FORWARD:
            case FORWARD:
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

void ccmd_destroy(ccmd_t** q) {
    check(q, "ccmd_destroy() error - Initialize queue first");

    ccmd_node_t* curr = (*q)->head;
    ccmd_node_t* tmp = NULL;
    while (curr) {
        tmp = curr->next;
        free(curr);
        curr = tmp;
    }

    free(*q);
    *q = NULL;
}

void ccmd_log(ccmd_t* q) {
    check(q, "ccmd_log() error - Initialize queue first");
    printf("ccmd ");

    ccmd_node_t* curr = q->head;

    while (curr) {
        char opts[64] = "";

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
            case MULTI_FORWARD:
            case FORWARD:
                sprintf(opts, "%s://%s:%d,%sb", curr->fwd.proto == TCP ? "tcp" : "udp", inet_ntoa((struct in_addr) {curr->fwd.fwd_host}), ntohs(curr->fwd.fwd_port), pd_str(&curr->pd_val));
                break;
            case REPLY:
                sprintf(opts, "%sb,%d", pd_str(&curr->pd_val), curr->resp.n_ack);
                break;
            default: 
                fprintf(stderr, "ccmd_log() - Unknown command type\n");
                exit(EXIT_FAILURE);
        }
        printf("%s(%s)%s", get_command_name(curr->cmd), opts, curr->next ? "->" : "");
        curr = curr->next;
    }
    printf("\n");
}

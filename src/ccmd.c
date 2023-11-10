#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "ccmd.h"
#include "message.h"
#include "cw_debug.h"

void ccmd_init(ccmd_t** q) {
    *q = malloc(sizeof(ccmd_t));

    (*q)->num = 0;
    (*q)->last_reply_called = 0;

    (*q)->head_actions = NULL;
    (*q)->tail_actions = NULL;

    (*q)->head_replies = NULL;
    (*q)->tail_replies = NULL;
}

ccmd_node_t *ccmd_add(ccmd_t* q, command_type_t cmd, pd_spec_t *p_pd_spec) {
    if (!q) {
        printf("ccmd_add() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    ccmd_node_t* new_node = malloc(sizeof(ccmd_node_t));
    new_node->cmd = cmd;
    new_node->pd_val = *p_pd_spec;

    if (new_node->cmd != REPLY){ // FIFO
        if (!q->head_actions) {
            q->head_actions = new_node;
            q->tail_actions = new_node;
        }
        else {
            q->tail_actions->next = new_node;
            q->tail_actions = new_node;
        }

        new_node->next = q->head_replies;
    }
    else { //LIFO
        if (!q->head_replies) {
            q->tail_replies = new_node;
        }

        new_node->next = q->head_replies;
        q->head_replies = new_node;

        if (q->tail_actions) {
            q->tail_actions->next = new_node;
        }
    }

    q->num++;

    return new_node;
}

// No LIFO for last reply of the command chain
void ccmd_attach_last_reply(ccmd_t* q, pd_spec_t *p_pd_spec) {
    if (!q) {
        printf("ccmd_attach_last_reply() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    if (q->last_reply_called) {
        printf("ccmd_attach_last_reply() warning - you already called it, skipping...\n");
        return;
    }

    if (!q->head_replies) {
        ccmd_add(q, REPLY, p_pd_spec);
    }
    else {
        ccmd_node_t* new_node = malloc(sizeof(ccmd_node_t));
        new_node->next = NULL;
        new_node->cmd = REPLY;
        new_node->pd_val = *p_pd_spec;

        ccmd_node_t* tmp = q->tail_replies;
        q->tail_replies = new_node;
        tmp->next = new_node;
        new_node->next = NULL;

        q->num++;
    }

    q->last_reply_called = 1;
}

extern __thread struct drand48_data rnd_buf;

ccmd_node_t *ccmd_skip(ccmd_node_t *curr, int n) {
    int prev_was_mfwd = 0;
    while (n-- > 0) {
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
            } while (1);
        }
        prev_was_mfwd = (curr->cmd == MULTI_FORWARD);
        curr = curr->next;
    }
    return curr;
}

void ccmd_dump(ccmd_t* q, message_t* m) {
    check(q, "ccmd_dump() error - Initialize queue first");
    check(m, "ccmd_dump() error - NullPointer message_t*");

    ccmd_node_t* curr = q->head_actions;
    int num = q->num;

    double x = 0;
    command_t *cmd = message_first_cmd(m);

    while (curr) {
        cmd->cmd = curr->cmd;

        switch (curr->cmd) {
            case STORE:
                cmd_get_opts(store_opts_t, cmd)->store_nbytes = pd_sample(&curr->pd_val);
                break;
            case COMPUTE:
                cmd_get_opts(comp_opts_t, cmd)->comp_time_us = pd_sample(&curr->pd_val);
                break;
            case LOAD:
                cmd_get_opts(load_opts_t, cmd)->load_nbytes = pd_sample(&curr->pd_val);
                break;
            case REPLY: 
                *cmd_get_opts(reply_opts_t, cmd) = curr->resp;
                cmd_get_opts(reply_opts_t, cmd)->resp_size = pd_sample(&curr->pd_val);
                break;
            case PSKIP:
                drand48_r(&rnd_buf, &x);
                cw_log("skip: x=%g, prob=%g\n", x, curr->pd_val.val);
                if (x <= curr->pd_val.val) {
                    num -= curr->n_skip;
                    curr = ccmd_skip(curr, curr->n_skip);
                }
                num--;
                break;
            case MULTI_FORWARD:
            case FORWARD:
                *cmd_get_opts(fwd_opts_t, cmd) = curr->fwd;
                cmd_get_opts(fwd_opts_t, cmd)->pkt_size = pd_sample(&curr->pd_val);
                break;
            default: 
                fprintf(stderr, "ccmd_dump() - Unknown command type\n");
                exit(EXIT_FAILURE);
        }
        cmd = cmd_next(cmd);
        //printf("%s\n", get_command_name(curr->cmd));
        curr = curr->next;
    }
    cmd->cmd = EOM;

    m->num = num + 1;
}

void ccmd_destroy(ccmd_t* q) {
    check(q, "ccmd_destroy() error - Initialize queue first");

    ccmd_node_t* curr = q->head_actions;
    ccmd_node_t* tmp = NULL;
    while (curr) {
        tmp = curr->next;
        free(curr);
        curr = tmp;
    }

    free(q);
}

void ccmd_log(ccmd_t* q) {
    check(q, "ccmd_log() error - Initialize queue first");

    ccmd_node_t* curr = q->head_actions;

    while (curr) {
        char opts[32] = "";

        switch (curr->cmd) {
            case STORE:
                sprintf(opts, "%sb", pd_str(&curr->pd_val));
                break;
            case COMPUTE:
                sprintf(opts, "%sus", pd_str(&curr->pd_val));
                break;
            case LOAD:
                sprintf(opts, "%sb", pd_str(&curr->pd_val));
                break;
            case PSKIP:
                if (curr->pd_val.val < 1.0)
                    sprintf(opts, "%d,prob=%s", curr->n_skip, pd_str(&curr->pd_val));
                else
                    sprintf(opts, "%d", curr->n_skip);
                break;
            case MULTI_FORWARD:
            case FORWARD:
                sprintf(opts, "%s:%d,%sb", inet_ntoa((struct in_addr) {curr->fwd.fwd_host}), ntohs(curr->fwd.fwd_port), pd_str(&curr->pd_val));
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

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ccmd.h"
#include "message.h"

void ccmd_init(ccmd_t** q) {
    *q = malloc(sizeof(ccmd_t));

    (*q)->num = 0;
    (*q)->last_reply_called = 0;

    (*q)->head_actions = NULL;
    (*q)->tail_actions = NULL;

    (*q)->head_replies = NULL;
    (*q)->tail_replies = NULL;
}

void ccmd_add(ccmd_t* q, command_type_t cmd, pd_spec_t *p_pd_spec) {
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

        q->tail_actions->next = new_node;
    }

    q->num++;
}

void ccmd_attach_reply_size(ccmd_t* q, pd_spec_t *p_pd_spec) {
    if (!q) {
        printf("ccmd_attach_reply_size() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    if (!q->head_replies) {
        ccmd_last_reply(q, REPLY, p_pd_spec);
    } else {
        q->head_replies->pd_val = *p_pd_spec;
    }
}

// No LIFO for last reply of the command chain
void ccmd_last_reply(ccmd_t* q, command_type_t cmd, pd_spec_t *p_pd_spec) {
    if (!q) {
        printf("ccmd_last_reply() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    if (cmd != REPLY) {
        printf("ccmd_last_reply() error - Wrong command type\n");
        exit(EXIT_FAILURE);
    }

    if (q->last_reply_called) {
        printf("ccmd_last_reply() warning - you already called it, skipping...\n");
        return;
    }

    if (!q->head_replies) {
        ccmd_add(q, cmd, p_pd_spec);
    }
    else {
        ccmd_node_t* new_node = malloc(sizeof(ccmd_node_t));
        new_node->next = NULL;
        new_node->cmd = cmd;
        new_node->pd_val = *p_pd_spec;

        ccmd_node_t* tmp = q->tail_replies;
        q->tail_replies = new_node;
        tmp->next = new_node;
        new_node->next = NULL;

        q->num++;
    }

    q->last_reply_called = 1;
}

void ccmd_dump(ccmd_t* q, message_t* m) {
    if (!q) {
        printf("ccmd_dump() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    if (!m) {
        printf("ccmd_dump() error - NullPointer message_t* \n");
        exit(EXIT_FAILURE);
    }

    ccmd_node_t* curr = q->head_actions;

    int i = 0;
    while (curr) {
        m->cmds[i].cmd = curr->cmd;
        // doesn't really matter if we're filling up comp_time_us, resp_size, ...
        m->cmds[i++].u.comp_time_us = pd_sample(&curr->pd_val);

        switch (curr->cmd) {
            case STORE:
            case COMPUTE:
            case LOAD:
            case REPLY: 
                break;
            case FORWARD:
                m->cmds[i].u.fwd = curr->fwd;
                break;
            default: 
                printf("ccmd_dump() - Unknown command type\n");
                exit(EXIT_FAILURE);
        }
        //printf("%s\n", get_command_name(curr->cmd->cmd));
        curr = curr->next;
    }

    m->num = q->num;
}

void ccmd_destroy(ccmd_t* q) {
    if (!q) {
        printf("ccmd_destroy() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

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
    if (!q) {
        printf("ccmd_log() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

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
            case FORWARD:
                sprintf(opts, "%s:%d,%s", inet_ntoa((struct in_addr) {curr->fwd.fwd_host}), ntohs(curr->fwd.fwd_port), pd_str(&curr->pd_val));
                break;
            case REPLY:
                sprintf(opts, "%sb", pd_str(&curr->pd_val));
                break;
            default: 
                printf("ccmd_log() - Unknown command type\n");
                exit(EXIT_FAILURE);
        }
        printf("%s(%s)%s", get_command_name(curr->cmd), opts, curr->next ? "->" : "");
        curr = curr->next;
    }
    printf("\n");
}

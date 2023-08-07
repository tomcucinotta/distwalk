#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ccmd.h"
#include "message.h"
#include "cw_debug.h"

void ccmd_init(ccmd_t** q) {
    *q = malloc(sizeof(ccmd_t));

    (*q)->head_actions = NULL;
    (*q)->tail_actions = NULL;

    (*q)->head_replies = NULL;
    (*q)->num = 0;
}

void ccmd_add(ccmd_t* q, command_t* cmd) {
    if (!q) {
        printf("ccmd_add() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    ccmd_node_t* new_node = malloc(sizeof(ccmd_node_t));
    new_node->cmd = malloc(sizeof(command_t));
    memcpy(&(new_node->cmd), &cmd, sizeof(command_t));

    if (new_node->cmd->cmd != REPLY){ // FIFO
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

// No LIFO for last reply of the command chain
void ccmd_last_reply(ccmd_t* q, command_t* cmd) {
    if (!q) {
        printf("ccmd_last_reply() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    if (cmd->cmd != REPLY) {
        printf("ccmd_last_reply() error - Wrong command type\n");
        exit(EXIT_FAILURE);
    }

    if (!q->head_replies) {
        ccmd_add(q, cmd);
    }
    else {
        ccmd_node_t* new_node = malloc(sizeof(ccmd_node_t));
        new_node->next = NULL;
        new_node->cmd = malloc(sizeof(command_t));
        memcpy(&(new_node->cmd), &cmd, sizeof(command_t));

        ccmd_node_t* tmp = q->tail_replies;
        q->tail_replies = new_node;
        tmp->next = new_node;
        new_node->next = NULL;

        q->num++;
    }
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
    ccmd_node_t* prec = NULL;

    int i = 0;
    while (curr) {
        // Chain validity check
        if (prec && prec->cmd->cmd == FORWARD && curr->cmd->cmd == FORWARD) {
            printf("ccmd_dump() error - Two contiguous forward operations\n");
            exit(EXIT_FAILURE);
        }

        m->cmds[i].cmd = curr->cmd->cmd;
        m->cmds[i++].u = curr->cmd->u;

        switch (curr->cmd->cmd) {
            case STORE:
                m->req_size += curr->cmd->u.store_nbytes;
            case COMPUTE:
            case LOAD:
            case FORWARD:
            case REPLY: 
                break;
            default: 
                printf("Unknown command type\n");
                exit(EXIT_FAILURE);
        }
        //printf("%s\n", get_command_name(curr->cmd->cmd));
        prec = curr;
        curr = curr->next;
    }

    m->num = q->num;
}

void ccmd_log(ccmd_t* q) {
    if (!q) {
        printf("ccmd_dump() error - Initialize queue first\n");
        exit(EXIT_FAILURE);
    }

    ccmd_node_t* curr = q->head_actions;

    while (curr) {
        char opts[32] = "";

        switch (curr->cmd->cmd) {
            case STORE:
                sprintf(opts, "%db", curr->cmd->u.store_nbytes);
                break;
            case COMPUTE:
                sprintf(opts, "%dus", curr->cmd->u.comp_time_us);
                break;
            case LOAD:
                sprintf(opts, "%db", curr->cmd->u.load_nbytes);
                break;
            case FORWARD:
                sprintf(opts, "%s:%d", inet_ntoa((struct in_addr) {curr->cmd->u.fwd.fwd_host}), ntohs(curr->cmd->u.fwd.fwd_port));
                break;
            case REPLY:
                //sprintf(opts, "%dus", curr->cmd->u.pkt_size);
                break;
            default: 
                printf("Unknown command type\n");
                exit(EXIT_FAILURE);
        }
        cw_log("%s(%s)%s", get_command_name(curr->cmd->cmd), opts, curr->next ? "->" : "");
        curr = curr->next;
    }
    cw_log("\n");
}

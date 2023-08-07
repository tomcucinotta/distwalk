#include "message.h"

/*
    Hybrid queue-stack
    - FIFO for "action" commands (i.e., COMPUTE, STORE, LOAD, FORWARD)
    - LIFO for reply commands, except last one
*/
typedef struct ccmd_node_t {
    command_t* cmd;
    struct ccmd_node_t* next;
} ccmd_node_t;

typedef struct ccmd_queue_t {
    uint8_t num;

    ccmd_node_t* head_actions;
    ccmd_node_t* tail_actions;

    ccmd_node_t* head_replies;
    ccmd_node_t* tail_replies;
} ccmd_t;


void ccmd_init(ccmd_t** q);
void ccmd_add(ccmd_t* q, command_t* cmd);
void ccmd_last_reply(ccmd_t* q, command_t* cmd);
void ccmd_dump(ccmd_t* q, message_t* m);
#ifdef CW_DEBUG
void ccmd_log(ccmd_t* q);
#endif

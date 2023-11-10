#include "request.h"
#include "cw_debug.h"
#include <string.h>

req_info_t reqs[MAX_REQS];
int last_reqs = 0;

void req_init() {
    // Tag all req as unused
    for (int i = 0; i < MAX_REQS; i++) {
        memset(&reqs[i], 0, sizeof(req_info_t));
        reqs[i].req_id = -1;
        reqs[i].conn_id = -1;
    }

}

message_t* req_get_message(req_info_t *r) {
    return (message_t*)r->message_ptr;
}

req_info_t* req_free(req_info_t* r) {
    cw_log("REQUEST remove req_id:%d\n", r->req_id);

    req_info_t *next;
    r->req_id = -1;
    next = r->next;
    if (r->next != NULL)
        r->next->prev = r->prev;
    if (r->prev != NULL)
        r->prev->next = r->next;
    r->next = NULL;
    r->prev = NULL;

    return next;
}

req_info_t* req_alloc() {
    int req_id = __atomic_fetch_add(&last_reqs, 1, __ATOMIC_SEQ_CST);
    req_info_t *r = &reqs[req_id % MAX_REQS];

    if (r->req_id != -1)
        return NULL;

    r->req_id = req_id;
    r->curr_cmd_id = 0;
    r->next = NULL;
    r->prev = NULL;

    return r;
}

req_info_t *req_get_by_id(int req_id) {
    if (reqs[req_id % MAX_REQS].req_id != req_id)
        return NULL;
    return &reqs[req_id % MAX_REQS];
}
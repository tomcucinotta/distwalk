#include "request.h"
#include "dw_debug.h"
#include <string.h>

req_info_t reqs[MAX_REQS];
atomic_int last_reqs = 0;

void req_init() {
    // Tag all req as unused
    for (int i = 0; i < MAX_REQS; i++) {
        memset(&reqs[i], 0, sizeof(req_info_t));
        reqs[i].req_id = -1;
        reqs[i].conn_id = -1;
    }
}

req_info_t* req_free(req_info_t* r) {
    dw_log("REQUEST remove req_id:%d\n", r->req_id);

    req_info_t *next = r->next;
    if (r->next != NULL)
        r->next->prev = r->prev;
    if (r->prev != NULL)
        r->prev->next = r->next;
    r->next = NULL;
    r->prev = NULL;
    r->req_id = -1;

    return next;
}

req_info_t* req_alloc() {
    int req_id = atomic_fetch_add(&last_reqs, 1);
    req_info_t *r = &reqs[req_id % MAX_REQS];

    if (r->req_id != -1)
        return NULL;

    r->req_id = req_id;
    r->curr_cmd = NULL;
    r->fwd_replies_left = -1;
    r->fwd_retries = -1;
    r->next = NULL;
    r->prev = NULL;

    return r;
}

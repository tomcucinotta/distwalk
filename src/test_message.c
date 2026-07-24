#include <stdio.h>
#include <stdbool.h>

#include "message.h"
#include "dw_debug.h"

bool test_message_construct() {
    /* coverity[suspicious_sizeof] */
    message_t *m = (message_t *) calloc(BUF_SIZE, sizeof(unsigned char));
    m->req_size = BUF_SIZE;
    m->req_id = 0;
    void *msg_end = message_end(m);

    command_t *c_itr = message_first_cmd(m);
    c_itr->cmd = COMPUTE;
    cmd_get_opts(comp_opts_t, c_itr)->comp_time_us = 1000;
    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = COMPUTE;
    cmd_get_opts(comp_opts_t, c_itr)->comp_time_us = 2000;
    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = EOM;

    //invalid
    c_itr  = cmd_bounded_next(c_itr, msg_end);
    cmd_get_opts(comp_opts_t, c_itr)->comp_time_us = -1;

    if (msg_num_cmd(m) != 2)
        goto err;

    for (command_t *itr = message_first_cmd(m); itr && itr->cmd != EOM; itr = cmd_bounded_next(itr, msg_end)) {
        int comp_us = cmd_get_opts(comp_opts_t, itr)->comp_time_us;
        if (itr->cmd != COMPUTE || (comp_us != 1000 && comp_us != 2000))
            goto err;
    }

    free(m);
    return true;

    err:
    free(m);
    return false;
}

bool test_message_copy_no_append() {
    /* coverity[suspicious_sizeof] */
    message_t *m = (message_t *) calloc(BUF_SIZE, sizeof(unsigned char));
    m->req_size = BUF_SIZE;
    m->req_id = 0;
    void *msg_end = message_end(m);

    command_t *c_itr = message_first_cmd(m);
    cmd_get_opts(comp_opts_t, c_itr)->comp_time_us = 1000;
    c_itr = cmd_bounded_next(c_itr, msg_end);
    cmd_get_opts(comp_opts_t, c_itr)->comp_time_us = 2000;
    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = EOM;

    /* coverity[suspicious_sizeof] */
    message_t *m_dst = (message_t *) malloc(BUF_SIZE);
    m_dst->req_size = BUF_SIZE;
    void *msg_end_dst = message_end(m_dst);
    message_first_cmd(m_dst)->cmd = EOM;
    
    if (!message_copy_tail(m, m_dst, message_first_cmd(m)))
        goto err;
    if (msg_num_cmd(m_dst) != 2)
        goto err;
    for (command_t *itr = message_first_cmd(m_dst); itr && itr->cmd != EOM; itr = cmd_bounded_next(itr, msg_end_dst)) {
        int comp_us = cmd_get_opts(comp_opts_t, itr)->comp_time_us;
        if (itr->cmd != COMPUTE || (comp_us != 1000 && comp_us != 2000))
            goto err;
    }


    if (!message_copy_tail(m, m_dst, cmd_bounded_next(message_first_cmd(m), msg_end)))
        goto err;
    if (msg_num_cmd(m_dst) != 1)
        goto err;
    
    c_itr = message_first_cmd(m_dst);
    if (c_itr->cmd != COMPUTE || cmd_get_opts(comp_opts_t, c_itr)->comp_time_us != 2000)
        goto err;

    free(m);
    free(m_dst);
    return true;

    err:
    free(m);
    free(m_dst);
    return false;
}

bool test_message_copy_with_reply() {
    /* coverity[suspicious_sizeof] */
    message_t *m = (message_t *) (message_t *) calloc(BUF_SIZE, sizeof(unsigned char));;
    m->req_size = BUF_SIZE;
    m->req_id = 0;
    void *msg_end = message_end(m);

    command_t *c_itr = message_first_cmd(m);
    cmd_get_opts(comp_opts_t, c_itr)->comp_time_us = 1000;
    c_itr->cmd = COMPUTE;
    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = REPLY;
    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = COMPUTE;
    cmd_get_opts(comp_opts_t, c_itr)->comp_time_us = 2000;
    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = EOM;

    /* coverity[suspicious_sizeof] */
    message_t *m_dst = (message_t *) malloc(BUF_SIZE);
    m_dst->req_size = BUF_SIZE;
    void *msg_end_dst = message_end(m_dst);
    message_first_cmd(m_dst)->cmd = EOM;

    if (!message_copy_tail(m, m_dst, message_first_cmd(m)))
        goto err;
    if (msg_num_cmd(m_dst) != 2)
        goto err;
    
    for (command_t *itr = message_first_cmd(m_dst); itr && itr->cmd != EOM; itr = cmd_bounded_next(itr, msg_end_dst)) {
        int comp_us = cmd_get_opts(comp_opts_t, itr)->comp_time_us;
        if (itr->cmd != REPLY && (itr->cmd == COMPUTE && comp_us != 1000))
            goto err;
    }

    free(m);
    free(m_dst);
    return true;

    err:
    free(m);
    free(m_dst);
    return false;
}

bool test_message_copy_fragment() {
    /* coverity[suspicious_sizeof] */
    message_t *m = (message_t *) calloc(BUF_SIZE, sizeof(unsigned char));
    m->req_size = BUF_SIZE;
    m->req_id = 0;
    void *msg_end = message_end(m);

    command_t *c_itr = message_first_cmd(m);
    c_itr->cmd = FORWARD_BEGIN;
    cmd_get_opts(fwd_opts_t, c_itr)->branched = 1;

    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = STORE;
    cmd_get_opts(store_opts_t, c_itr)->store_nbytes = 1000;

    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = REPLY;

    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = FORWARD_CONTINUE;
    cmd_get_opts(fwd_opts_t, c_itr)->branched = 1;

    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = LOAD;
    cmd_get_opts(load_opts_t, c_itr)->load_nbytes = 2000;

    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = REPLY;

    c_itr = cmd_bounded_next(c_itr, msg_end);
    cmd_get_opts(comp_opts_t, c_itr)->comp_time_us = 3000;

    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = REPLY;

    c_itr = cmd_bounded_next(c_itr, msg_end);
    c_itr->cmd = EOM;

    /* coverity[suspicious_sizeof] */
    message_t *m_branch1 = (message_t *) calloc(BUF_SIZE, sizeof(unsigned char));
    m_branch1->req_size = BUF_SIZE;
    void *msg_end_branch = message_end(m_branch1);
    m->req_id = 0;
    
    command_t *c = cmd_bounded_next(message_first_cmd(m), msg_end);
    while (c && c->cmd != EOM && c->cmd == FORWARD_CONTINUE)
        c = cmd_bounded_next(c, msg_end);
    if (!message_copy_tail(m, m_branch1, c))
        goto err;

    // check
    c_itr = message_first_cmd(m_branch1);

    if (!c_itr || c_itr->cmd != STORE)
        goto err;
    c_itr = cmd_bounded_next(c_itr, msg_end_branch);
    if (!c_itr || c_itr->cmd != REPLY)
        goto err;

    free(m);
    free(m_branch1);
    return true;

    err:
    free(m);
    free(m_branch1);
    return false;
}

int main() {
    bool rv = true;
    rv &= perform_test(test_message_construct());
    rv &= perform_test(test_message_copy_no_append());
    rv &= perform_test(test_message_copy_with_reply());
    rv &= perform_test(test_message_copy_fragment());
    return rv ? EXIT_SUCCESS : EXIT_FAILURE;
}

#include <stdio.h>
#include <stdbool.h>

#include "ccmd.h"
#include "message.h"
#include "dw_debug.h"
bool test_ccmd_init_destroy() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    if (ccmd == NULL || sizeof(*ccmd) != sizeof(ccmd_t)) {
        return false;
    }

    ccmd_destroy(&ccmd);
    if (ccmd == NULL) {
        return true;
    }

    return false;
}

bool test_ccmd_add_1() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    bool res = false;
    if (ccmd->num == 1                           && 
        ccmd->head == ccmd->tail &&
        ccmd->head->cmd == COMPUTE       &&
        ccmd->head->pd_val.val == 100) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_add_2() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, STORE, &val);

    bool res = false;
    if (ccmd->num == 2                &&
        ccmd->head->cmd == COMPUTE    &&
        ccmd->head->pd_val.val == 100 && 
        ccmd->tail->cmd == STORE      && 
        ccmd->tail->pd_val.val == 200) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_add_3() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);
    
    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (ccmd->num == 1                           &&
        ccmd->head == ccmd->tail &&
        ccmd->head->cmd == REPLY         &&
        ccmd->head->pd_val.val == 100) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_add_4() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (ccmd->num == 2                           &&
        ccmd->head != ccmd->tail &&
        ccmd->head->cmd == COMPUTE       &&
        ccmd->head->pd_val.val == 100    && 
        ccmd->tail->cmd == REPLY         && 
        ccmd->tail->pd_val.val == 200) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_last() {
    bool res = false;

    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, LOAD, &val);
    if (ccmd_last(ccmd)->cmd == LOAD && ccmd_last(ccmd)->pd_val.val == 400) {
        res = true;
    }

    val = pd_build_fixed(500);
    ccmd_add(ccmd, REPLY, &val);
        if (ccmd_last(ccmd)->cmd == REPLY && ccmd_last(ccmd)->pd_val.val == 500) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_last_reply() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, FORWARD, &val);

    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(500);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (ccmd_last(ccmd)->cmd == REPLY   &&
        ccmd_last(ccmd)->pd_val.val == 500) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_attach_last_reply_1() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (ccmd->num == 3                    &&
        ccmd->tail->cmd == REPLY  && 
        ccmd->tail->pd_val.val == 300) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_attach_last_reply_2() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (ccmd->num == 4                        &&
        ccmd->tail->pd_val.val == 400) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_skip_1() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, REPLY, &val);

    ccmd_node_t* cmd = ccmd_skip(ccmd->head, 2);

    bool res = false;
    if (cmd->cmd == REPLY && cmd->pd_val.val == 300) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_skip_2() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    ccmd_node_t* cmd = ccmd_skip(ccmd->head, 10);

    bool res = false;
    if (cmd == NULL) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_skip_3() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(200);
    ccmd_add(ccmd, FORWARD, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(500);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(600);
    ccmd_add(ccmd, COMPUTE, &val);

    ccmd_node_t* cmd = ccmd_skip(ccmd->head, 1);

    bool res = false;
    if (cmd != NULL && cmd->cmd == FORWARD && cmd->pd_val.val == 200) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_skip_4() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, FORWARD, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, LOAD, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(500);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(600);
    ccmd_add(ccmd, COMPUTE, &val);


    ccmd_node_t* cmd = ccmd_skip(ccmd->head, 1);

    bool res = false;
    if (cmd != NULL && cmd->cmd == COMPUTE && cmd->pd_val.val == 500) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_dump() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, STORE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, PSKIP, &val);
    ccmd_last(ccmd)->n_skip = 2;

    val = pd_build_fixed(400);
    ccmd_add(ccmd, LOAD, &val);

    
    val = pd_build_fixed(500);
    ccmd_add(ccmd, FORWARD, &val);
    
    val = pd_build_fixed(600);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(700);
    ccmd_add(ccmd, LOAD, &val);

    val = pd_build_fixed(800);
    ccmd_add(ccmd, REPLY, &val);


    val = pd_build_fixed(900);
    ccmd_add(ccmd, REPLY, &val);

    unsigned char *send_buf = malloc(BUF_SIZE);
    message_t *m = (message_t *)send_buf;
    m->req_size = BUF_SIZE;

    ccmd_dump(ccmd, m);

    bool res = false;

    command_t *c = message_first_cmd(m);
    if (c->cmd != STORE) {
        res = false;
        goto err;
    }

    c = cmd_next(c);
    if (c->cmd != COMPUTE) {
        res = false;
        goto err;
    }

    c = cmd_next(c);
    if (c->cmd != REPLY && cmd_get_opts(reply_opts_t, c)->resp_size == 900) {
        res = false;
        goto err;
    }

    c = cmd_next(c);
    if (c->cmd != EOM) {
        res = false;
        goto err;
    }

    res = true;

    err:
        ccmd_destroy(&ccmd);
        free(m);
        return res;
}  

int main() {
    perform_test(test_ccmd_init_destroy());
    perform_test(test_ccmd_add_1());
    perform_test(test_ccmd_add_2());
    perform_test(test_ccmd_add_3());
    perform_test(test_ccmd_add_4());
    perform_test(test_ccmd_last());
    perform_test(test_ccmd_last_reply());
    perform_test(test_ccmd_attach_last_reply_1());
    perform_test(test_ccmd_attach_last_reply_2());
    perform_test(test_ccmd_skip_1());
    perform_test(test_ccmd_skip_2());
    perform_test(test_ccmd_skip_3());
    perform_test(test_ccmd_skip_4());
    perform_test(test_ccmd_dump());

    return 0;
}

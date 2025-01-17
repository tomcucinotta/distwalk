#include <stdio.h>
#include <stdbool.h>

#include "ccmd.h"
#include "message.h"
#include "dw_debug.h"

bool test_ccmd_init_destroy() {
    queue_t* ccmd = queue_alloc(2);
    if (!ccmd || sizeof(*ccmd) != sizeof(queue_t))
        return false;

    ccmd_destroy(&ccmd);
    if (ccmd) 
        return false;
    return true;
}

bool test_ccmd_add_1() {
    queue_t* ccmd = queue_alloc(1);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);

    bool res = false;
    if (queue_size(ccmd) == 1                           
        && ccmd->head == ccmd->tail
        && ccmd_last(ccmd)->cmd == COMPUTE    
        && ccmd_last(ccmd)->pd_val.val == 100) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_add_2() {
    queue_t* ccmd = queue_alloc(2);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, STORE, &val);

    bool res = false;
    if (queue_size(ccmd) == 2                
        && ccmd_first(ccmd)->cmd == COMPUTE    
        && ccmd_first(ccmd)->pd_val.val == 100 
        && ccmd_last(ccmd)->cmd == STORE
        && ccmd_last(ccmd)->pd_val.val == 200) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_add_3() {
    queue_t* ccmd = queue_alloc(2);
    
    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (queue_size(ccmd) == 1
        && ccmd->head == ccmd->tail
        && queue_head(ccmd)->key == REPLY
        && ccmd_first(ccmd)->pd_val.val == 100) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_add_4() {
    queue_t* ccmd = queue_alloc(2);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (queue_size(ccmd) == 2
        && ccmd->head != ccmd->tail 
        && queue_head(ccmd)->key == COMPUTE
        && ccmd_first(ccmd)->pd_val.val == 100
        && queue_tail(ccmd)->key == REPLY
        && ccmd_last(ccmd)->pd_val.val == 200) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_last() {
    bool res = false;

    queue_t* ccmd = queue_alloc(5);

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
    queue_t* ccmd = queue_alloc(5);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, FORWARD_BEGIN, &val);

    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(500);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (ccmd_last(ccmd)->cmd == REPLY
        && ccmd_last(ccmd)->pd_val.val == 500) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_attach_last_reply_1() {
    queue_t* ccmd = queue_alloc(3);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (queue_size(ccmd) == 3 
        && queue_tail(ccmd)->key == REPLY 
        && ccmd_last(ccmd)->pd_val.val == 300) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_attach_last_reply_2() {
    queue_t* ccmd = queue_alloc(4);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, REPLY, &val);

    bool res = false;
    if (queue_size(ccmd) == 4
        && ccmd_last(ccmd)->pd_val.val == 400) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_skip_1() {
    queue_t* ccmd = queue_alloc(4);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, REPLY, &val);
    
    ccmd_node_t* cmd = ccmd_skip(ccmd_first(ccmd), 2);

    bool res = false;
    if (cmd->cmd == REPLY && cmd->pd_val.val == 300) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_skip_2() {
    queue_t* ccmd = queue_alloc(4);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);
    
    val = pd_build_fixed(200);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(300);
    ccmd_add(ccmd, REPLY, &val);

    ccmd_node_t* cmd = ccmd_skip((ccmd_node_t*) queue_node_data(queue_head(ccmd)).ptr, 10);

    bool res = false;
    if (cmd == NULL) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_skip_3() {
    queue_t* ccmd = queue_alloc(6);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(200);
    ccmd_add(ccmd, FORWARD_BEGIN, &val);
    
    val = pd_build_fixed(300);
    ccmd_add(ccmd, STORE, &val);

    val = pd_build_fixed(400);
    ccmd_add(ccmd, REPLY, &val);

    val = pd_build_fixed(500);
    ccmd_add(ccmd, COMPUTE, &val);

    val = pd_build_fixed(600);
    ccmd_add(ccmd, COMPUTE, &val);

    ccmd_node_t* cmd = ccmd_skip((ccmd_node_t*) queue_node_data(queue_head(ccmd)).ptr, 1);

    bool res = false;
    if (cmd != NULL && cmd->cmd == FORWARD_BEGIN && cmd->pd_val.val == 200) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_skip_4() {
    queue_t* ccmd = queue_alloc(6);

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, FORWARD_BEGIN, &val);
    
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

    ccmd_node_t* cmd = ccmd_skip((ccmd_node_t*) queue_node_data(queue_head(ccmd)).ptr, 1);

    bool res = false;
    if (cmd != NULL && cmd->cmd == COMPUTE && cmd->pd_val.val == 500) {
        res = true;
    }

    ccmd_destroy(&ccmd);
    return res;
}

bool test_ccmd_dump() {
    queue_t* ccmd = queue_alloc(9);

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
    ccmd_add(ccmd, FORWARD_BEGIN, &val);
    
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
    int rv = 0;
    perform_test(test_ccmd_init_destroy(), rv);
    perform_test(test_ccmd_add_1(), rv);
    perform_test(test_ccmd_add_2(), rv);
    perform_test(test_ccmd_add_3(), rv);
    perform_test(test_ccmd_add_4(), rv);
    perform_test(test_ccmd_last(), rv);
    perform_test(test_ccmd_last_reply(), rv);
    perform_test(test_ccmd_attach_last_reply_1(), rv);
    perform_test(test_ccmd_attach_last_reply_2(), rv);
    perform_test(test_ccmd_skip_1(), rv);
    perform_test(test_ccmd_skip_2(), rv);
    perform_test(test_ccmd_skip_3(), rv);
    perform_test(test_ccmd_skip_4(), rv);
    perform_test(test_ccmd_dump(), rv);
    return !rv;
}

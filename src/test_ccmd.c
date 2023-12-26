#include <stdio.h>

#include "ccmd.h"
#include "message.h"

int main() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    unsigned char *send_buf = malloc(BUF_SIZE);
    message_t *m = (message_t *)send_buf;
    m->req_size = BUF_SIZE;

    pd_spec_t val = pd_build_fixed(100);
    ccmd_add(ccmd, COMPUTE, &val);

    pd_spec_t val2 = pd_build_fixed(100);
    ccmd_add(ccmd, REPLY, &val2);
    //ccmd_last_reply(ccmd)->resp.n_ack = 1;

    ccmd_log(ccmd);
    ccmd_dump(ccmd, m);
    ccmd_destroy(ccmd);

    msg_log(m, "");

    free(m);

    return 0;
}

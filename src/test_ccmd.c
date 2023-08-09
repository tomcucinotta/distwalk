#include <stdio.h>

#include "ccmd.h"
#include "message.h"

int main() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    unsigned char *send_buf = malloc(BUF_SIZE);
    message_t *m = (message_t *)send_buf;

    command_t cmd1;
    cmd1.cmd = COMPUTE;
    cmd1.u.comp_time_us = 100;
    ccmd_add(ccmd, &cmd1);

    command_t cmd2;
    cmd2.cmd = REPLY;
    ccmd_add(ccmd, &cmd2);

    ccmd_log(ccmd);
    ccmd_dump(ccmd, m);
    ccmd_destroy(ccmd);
    
    msg_log(m);

    free(m);

    return 0;
}

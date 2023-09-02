#include <stdio.h>

#include "ccmd.h"
#include "message.h"

int main() {
    ccmd_t* ccmd;
    ccmd_init(&ccmd);

    unsigned char *send_buf = malloc(BUF_SIZE);
    message_t *m = (message_t *)send_buf;

    pd_spec_t val = { .prob = FIXED, .val = 100, .min = 0, .max = 0 };
    ccmd_add(ccmd, COMPUTE, &val);

    pd_spec_t val2 = { .prob = FIXED, .val = 100, .min = 0, .max = 0 };
    ccmd_add(ccmd, REPLY, &val2);

    ccmd_log(ccmd);
    ccmd_dump(ccmd, m);
    ccmd_destroy(ccmd);

    msg_log(m, "");

    free(m);

    return 0;
}

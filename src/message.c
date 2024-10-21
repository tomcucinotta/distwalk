#include "message.h"
#include <string.h>
#include <stdlib.h>

#ifndef min
#   define min(a, b) ((a)>(b)?(b):(a))
#endif

inline const char *proto_str(proto_t proto) {
    static const char *proto_str[PROTO_NUMBER] = {
        "UDP",
        "TCP",
    };
    return proto_str[proto];
}

inline const char* get_command_name(command_type_t cmd) {
    switch (cmd) {
    case COMPUTE: return "COMPUTE";
    case STORE: return "STORE";
    case LOAD: return "LOAD";
    case PSKIP: return "SKIP";
    case FORWARD: return "FORWARD";
    case MULTI_FORWARD: return "MULTI_FORWARD";
    case REPLY: return "REPLY";
    case EOM: return "EOM";
    default: 
        printf("Unknown command type\n");
        exit(EXIT_FAILURE);
    }
}

inline int cmd_type_size(command_type_t type) {
    int base = sizeof(command_t);
    switch (type) {
    case REPLY:
        return base + sizeof(reply_opts_t);
    case MULTI_FORWARD:
    case FORWARD:
        return base + sizeof(fwd_opts_t);
    case COMPUTE:
        return base + sizeof(comp_opts_t);
    case LOAD:
        return base + sizeof(load_opts_t);
    case STORE:
        return base + sizeof(store_opts_t);
    case PSKIP:
    case EOM:
        return base;
    }
    return base;
}

inline command_t* cmd_next(command_t *c) {
    unsigned char *ptr = (unsigned char*)c;
    ptr += cmd_type_size(c->cmd);
    return (command_t*) ptr;
}

inline command_t* message_first_cmd(message_t *m) {
    return &m->cmds[0];
}

// copy a message, and its commands starting from cmd until the matching REPLY is found
// m_dst->req_size should contain the available size
command_t* message_copy_tail(message_t *m, message_t *m_dst, command_t *cmd) {
    // copy message header
    m_dst->req_id = m->req_id;
    command_t *itr = cmd;
    while (itr->cmd != EOM && itr->cmd != REPLY)
        itr = message_skip_cmds(m, cmd, 1);
    command_t *reply_cmd = itr;
    itr = cmd_next(itr);
    int cmds_len = ((unsigned char*)itr - (unsigned char*)cmd);
    int skipped_len = ((unsigned char*)cmd - (unsigned char*)message_first_cmd(m));
    if (m_dst->req_size < cmds_len + cmd_type_size(EOM))
      return NULL;

    memcpy(m_dst->cmds, cmd, cmds_len);
    command_t* end_command = (command_t*)((unsigned char*)&m_dst->cmds[0] + cmds_len);
    end_command->cmd = EOM;
    m_dst->req_size = min(m_dst->req_size, m->req_size - skipped_len);

    return reply_cmd;
}

command_t* message_skip_cmds(message_t* m, command_t *cmd, int to_skip) {
    int skipped = to_skip;
    command_t *itr = cmd;

    while (itr->cmd != EOM && skipped > 0) {
        int nested_fwd = 0;

        do {
            if (itr->cmd == FORWARD)
                nested_fwd++;
            else if (itr->cmd == MULTI_FORWARD) {
                nested_fwd++;
                while (cmd_next(itr)->cmd == MULTI_FORWARD)
                    itr = cmd_next(itr);
            } else if (itr->cmd == REPLY)
                nested_fwd--;
            itr = cmd_next(itr);
        } while (itr->cmd != EOM && nested_fwd > 0);

        skipped--;
    }

    return itr;
}

inline const void msg_log(message_t* m, char* padding) {
    printf("%s", padding);
    printf("message (req_id: %u, req_size: %u, num: %u, status: %d): ", m->req_id, m->req_size, msg_num_cmd(m), m->status);

    command_t *c = message_first_cmd(m), *pre_c;
    while (c->cmd != EOM) {
        char opts[64] = "";

        switch (c->cmd) {
        case STORE:
            sprintf(opts, "%ldb,%s,offset=%ld", cmd_get_opts(store_opts_t, c)->store_nbytes,
                    cmd_get_opts(store_opts_t, c)->wait_sync ? "sync" : "nosync",
                    (long)cmd_get_opts(store_opts_t, c)->offset);
            break;
        case COMPUTE:
            sprintf(opts, "%dus", cmd_get_opts(comp_opts_t, c)->comp_time_us);
            break;
        case LOAD:
            sprintf(opts, "%ldb,offset=%ld", cmd_get_opts(load_opts_t, c)->load_nbytes,
                    (long)cmd_get_opts(load_opts_t, c)->offset);
            break;
        case MULTI_FORWARD:
        case FORWARD:
            sprintf(opts, "%s://%s:%d,%u", cmd_get_opts(fwd_opts_t, c)->proto == TCP ? "tcp" : "udp", inet_ntoa((struct in_addr) {cmd_get_opts(fwd_opts_t, c)->fwd_host}), ntohs(cmd_get_opts(fwd_opts_t, c)->fwd_port), cmd_get_opts(fwd_opts_t, c)->pkt_size);
            break;
        case REPLY:
            sprintf(opts, "%db,%d", cmd_get_opts(reply_opts_t, c)->resp_size, cmd_get_opts(reply_opts_t, c)->n_ack);
            break;
        default: 
            printf("Unknown command type\n");
            exit(EXIT_FAILURE);
        }
        pre_c = c;
        c = cmd_next(c);
        printf("%s(%s)%s", get_command_name(pre_c->cmd), opts, "->");
    }
    printf("EOM");
    printf(" [%ld bytes]\n", (unsigned char*)c - (unsigned char*)message_first_cmd(m));
}

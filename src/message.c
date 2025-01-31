#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "message.h"
#include "dw_debug.h"

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
    case FORWARD_BEGIN: return "FORWARD_BEGIN";
    case FORWARD_CONTINUE: return "FORWARD_CONTINUE";
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
    case FORWARD_BEGIN:
    case FORWARD_CONTINUE:
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

// Move to the next command
inline command_t* cmd_next(command_t *cmd) {
    unsigned char *ptr = (unsigned char*)cmd;
    return (command_t*) (ptr + cmd_type_size(cmd->cmd));
}

// Skip to_skip contextes (i.e., a simple operation, or a collection of operation within a forward scope)
command_t* cmd_skip(command_t *cmd, int to_skip) {
    while (cmd->cmd != EOM && to_skip > 0) {
        int nested_fwd = 0;
        int more_fwd;
        do {
            more_fwd = 0;
            if (cmd->cmd == FORWARD_BEGIN) {
                nested_fwd++;
            } else if (cmd->cmd == FORWARD_CONTINUE) {
                if (cmd_get_opts(fwd_opts_t, cmd)->branched)
                    nested_fwd++;
                /* skip multiple (non-branching) FORWARD_CONTINUE following FORWARD_BEGIN */
            } else if (cmd->cmd == REPLY) {
                nested_fwd--;
                if (cmd_next(cmd)->cmd == FORWARD_CONTINUE) // must have branched=1
                    more_fwd = 1;
            }
            cmd = cmd_next(cmd);
        } while (cmd->cmd != EOM && (more_fwd || nested_fwd > 0));
        to_skip--;
    }

    return cmd;
}

// return next FORWARD in the same multi-FORWARD context, or NULL if there are none
command_t* cmd_next_forward(command_t *cmd) {
    check(cmd->cmd == FORWARD_CONTINUE || cmd->cmd == FORWARD_BEGIN);

    int branched = cmd_get_opts(fwd_opts_t, cmd)->branched;
    cmd = cmd_next(cmd);
    while (cmd->cmd != EOM && cmd->cmd != FORWARD_CONTINUE) {
        if (cmd->cmd == FORWARD_BEGIN)
            cmd = cmd_skip(cmd, 1);
        else if (cmd->cmd == REPLY && (!branched || cmd_next(cmd)->cmd != FORWARD_CONTINUE))
            // when branched, a REPLY is followed by a CONTINUE, or the FORWARD context is over;
            // when !branched, a REPLY terminates the FORWARD context
            return NULL;
        else
            cmd = cmd_next(cmd);
    }
    return cmd;
}

inline command_t* message_first_cmd(message_t *m) {
    return &m->cmds[0];
}

// copy a message and its commands starting from cmd until the matching REPLY is found, which is returned.
// m_dst->req_size should contain the available size. Optionally append to m_dst without
// replacing all the commands
command_t* message_copy_tail(message_t *m, message_t *m_dst, command_t *cmd) {
    // copy message header
    m_dst->req_id = m->req_id;

    // find matching reply
    command_t *itr = cmd;
    while (itr->cmd != EOM && itr->cmd != REPLY)
        itr = cmd_skip(itr, 1);
    //assert(itr->cmd != EOM);
    int cmds_len = ((unsigned char*)cmd_next(itr) - (unsigned char*)cmd);

    command_t * dst_itr = message_first_cmd(m_dst);
    if (m_dst->req_size < cmds_len + cmd_type_size(EOM)) // Check if enough space for EOM delimiter
      return NULL;
    memcpy(dst_itr, cmd, cmds_len);

    command_t* end_command = (command_t*)((unsigned char*)dst_itr + cmds_len);
    end_command->cmd = EOM;
    
    m_dst->req_size = (unsigned char*)cmd_next(end_command) - (unsigned char*)m_dst;
    //int skipped_len = ((unsigned char*)cmd - (unsigned char*)message_first_cmd(m));
    //m_dst->req_size = min(m_dst->req_size, m->req_size - skipped_len);
    return itr;
}

inline const void cmd_log(command_t* cmd) {
    command_t *c = cmd, *pre_c;
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
        case FORWARD_BEGIN:
        case FORWARD_CONTINUE:
            sprintf(opts, "%s://%s:%d,%u,retries=%d,timeout=%d,branched=%d,nack=%d", cmd_get_opts(fwd_opts_t, c)->proto == TCP ? "tcp" : "udp", 
                                                                            inet_ntoa((struct in_addr) {cmd_get_opts(fwd_opts_t, c)->fwd_host}), 
                                                                            ntohs(cmd_get_opts(fwd_opts_t, c)->fwd_port), cmd_get_opts(fwd_opts_t, c)->pkt_size, 
                                                                            cmd_get_opts(fwd_opts_t, c)->retries, cmd_get_opts(fwd_opts_t, c)->timeout,
                                                                            cmd_get_opts(fwd_opts_t, c)->branched, cmd_get_opts(fwd_opts_t, c)->n_ack);
            break;
        case REPLY:
            sprintf(opts, "%db", cmd_get_opts(reply_opts_t, c)->resp_size);
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
    printf(" [%ld bytes]\n", (unsigned char*)c - (unsigned char*)cmd);
}

inline const void msg_log(message_t* m, char* padding) {
    printf("%s", padding);
    printf("message (req_id: %u, req_size: %u, num: %u, status: %d): ", m->req_id, m->req_size, msg_num_cmd(m), m->status);
    cmd_log(message_first_cmd(m));
}

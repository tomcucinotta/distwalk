#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF_SIZE (16*1024*1024)

typedef enum { COMPUTE, STORE, LOAD, PSKIP, FORWARD_BEGIN, FORWARD_CONTINUE, REPLY, EOM } command_type_t;

typedef enum { UDP, TCP, TLS, PROTO_NUMBER } proto_t;

typedef struct {
    uint32_t pkt_size;    // size of forwarded packet
    in_addr_t fwd_host;   // target IP of host to forward to (network encoding)
    uint16_t fwd_port;    // target port (network encoding, for multiple nodes on same host)
    uint32_t timeout;     // timeout in microsecond (0 means no timeout)
    uint8_t retries;      // how many times to reply before failing
    uint8_t n_ack;        // forward-reply concern (number of acknowledgments)
    uint8_t on_fail_skip; // how many instructions skip after failing
    uint8_t branched;     // multi-branched forward
    proto_t proto;        // which transport protocol to use
} fwd_opts_t;

typedef struct {
    uint64_t offset;
    uint64_t load_nbytes;
} load_opts_t;

typedef struct {
    uint64_t offset;
    uint64_t store_nbytes;
    uint8_t wait_sync;
} store_opts_t;

typedef struct {
    uint32_t comp_time_us;
} comp_opts_t;

typedef struct {
    uint32_t resp_size;   // REPLY pkt size
} reply_opts_t;

// TODO: Here we need all quantities to be network-ordered
typedef struct {
    command_type_t cmd;  
    unsigned char opts[];
} command_t;
#define cmd_get_opts(type, cmd) ((type*)&(cmd->opts[0]))

// Data structure containing the data sent by the DistWalk Client
// TODO: Here we need all quantities to be network-ordered
typedef struct {
    uint32_t req_id;   // Client-side request id
    uint32_t req_size; // Overall message size in bytes, including commands and payload
    int8_t status;     // 0 success, error otherwise (tipically set by dw_node)
    command_t cmds[];  // Series of command_t with variable size
} message_t;

const char *proto_str(proto_t proto);
const char* get_command_name(command_type_t cmd);

command_t* message_copy_tail(message_t *m, message_t *m_dst, command_t *cmd);

command_t* cmd_next(command_t *cmd);
command_t* cmd_skip(command_t *cmd, int to_skip);
command_t* cmd_next_forward(command_t *cmd);

command_t* message_first_cmd(message_t *m);
int cmd_type_size(command_type_t type);

static inline int msg_num_cmd(message_t *m) {
    int n = 0;
    command_t *cmd = message_first_cmd(m);
    while ((char*)cmd - (char*)m < m->req_size && cmd->cmd != EOM) {
        n++;
        cmd = cmd_next(cmd);
    }
    return n;
}

const void msg_log(message_t* m, char* padding);
const void cmd_log(command_t* c);
#endif /* __MESSAGE_H__ */

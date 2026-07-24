#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF_SIZE (16*1024*1024)

typedef enum { COMPUTE, STORE, LOAD, PSKIP, FORWARD_BEGIN, FORWARD_CONTINUE, REPLY, EOM } command_type_t;

typedef enum { UDP, TCP, TLS, DPDK, PROTO_NUMBER } proto_t;

typedef enum { SUCCESS, TIMEOUT, ERR, MSG_STATUS_NUMBER } msg_status_t;

typedef struct {
    uint32_t pkt_size;    // size of forwarded packet
    union {
        struct {
            in_addr_t fwd_host;   // target IP of host to forward to (network encoding)
            uint16_t fwd_port;    // target port (network encoding, for multiple nodes on same host)
        };
        uint8_t fwd_addr[6];       // target MAC address (for DPDK)
    };
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
    uint8_t dev_id; // device id, 0 by default
} load_opts_t;

typedef struct {
    uint64_t offset;
    uint64_t store_nbytes;
    uint8_t wait_sync;
    uint8_t dev_id; // device id, 0 by default
} store_opts_t;

typedef struct {
    uint32_t comp_time_us;
} comp_opts_t;

// added reply mode options
typedef enum {
    REPLY_MODE_NORMAL = 0,
    REPLY_MODE_SENDFILE = 1,
} reply_mode_t;

typedef struct {
    uint32_t resp_size;   // REPLY pkt size
    reply_mode_t mode;   // NORMAL | SENDFILE
    uint8_t dev_id; // device id, 0 by default
} reply_opts_t;

// TODO: Here we need all quantities to be network-ordered
typedef struct {
    command_type_t cmd;  
    unsigned char opts[];
} command_t;
#define cmd_get_opts(type, cmd) ((type*)&((cmd)->opts[0]))

// Data structure containing the data sent by the DistWalk Client
// TODO: Here we need all quantities to be network-ordered
typedef struct {
    uint32_t req_id;   // Client-side request id
    uint32_t req_size; // Overall message size in bytes, including commands and payload
    msg_status_t status;
    command_t cmds[];  // Series of command_t with variable size
} message_t;

const char* proto_str(proto_t proto);
const char* msg_status_str(msg_status_t msg_status);
const char* get_command_name(command_type_t cmd);

command_t* message_copy_tail(message_t *m, message_t *m_dst, command_t *cmd);

command_t* cmd_bounded_next(command_t *cmd, void* msg_end);
command_t* cmd_bounded_skip(command_t *cmd, int to_skip, void* msg_end);
command_t* cmd_bounded_next_forward(command_t *cmd, void* msg_end);

command_t* message_first_cmd(message_t *m);
int cmd_type_size(command_type_t type);

static inline void* message_end(message_t *m) {
    return (char*)m + m->req_size;
}

// true if the command at cmd is in bounds of the message
static inline bool cmd_in_bounds(command_t *cmd, void *msg_end) {
    const char *start = (char*)cmd;
    const char *end = msg_end;

    // the header must be in bounds before we can read cmd->cmd
    if (start + sizeof(command_t) > end)
        return false;

    // then the opts need to be in bounds
    return start + cmd_type_size(cmd->cmd) <= end;
}

static inline int msg_num_cmd(message_t *m) {
    int n = 0;
    command_t *cmd = message_first_cmd(m);
    void* msg_end = message_end(m);
    while (cmd && cmd_in_bounds(cmd, msg_end) && cmd->cmd != EOM) {
        n++;
        cmd = cmd_bounded_next(cmd, msg_end);
    }
    return n;
}

const void msg_log(message_t* m, char* padding);
const void cmd_log(command_t* c, void* msg_end);
#endif /* __MESSAGE_H__ */

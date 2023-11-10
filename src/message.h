#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF_SIZE (16*1024*1024)

typedef enum { COMPUTE, STORE, LOAD, PSKIP, FORWARD, MULTI_FORWARD, REPLY, EOM } command_type_t;

typedef enum { UDP, TCP } proto_t;

typedef struct {
  uint32_t pkt_size;    // size of forwarded packet
  in_addr_t fwd_host;   // target IP of host to forward to (network encoding)
  uint16_t fwd_port;    // target port (network encoding, for multiple nodes on same host)
  uint32_t timeout;     // timeout in microsecond (0 means no timeout)
  uint8_t retries;      // how many times to reply before failing
  uint8_t on_fail_skip; // how many instructions skip after failing
  proto_t proto;        // which transport protocol to use
} fwd_opts_t;

typedef struct {
  uint32_t load_nbytes;
} load_opts_t;

typedef struct {
  uint32_t store_nbytes;
} store_opts_t;

typedef struct {
  uint32_t comp_time_us;
} comp_opts_t;

//TODO: consider whether to use this structs
/*typedef struct {
  uint64_t offset;
  uint32_t pkt_size;   // size of forwarded packet
} store_opts_t;
*/

typedef struct {
  uint32_t resp_size;      // REPLY pkt size
  uint8_t n_ack;         // reply concern
} reply_opts_t;

// TODO: Here we need all quantities to be network-ordered
typedef struct {
  command_type_t cmd;  
  unsigned char opts[];
} command_t;
#define cmd_get_opts(type, cmd) ((type*)&(cmd->opts[0]))

// TODO: Here we need all quantities to be network-ordered
typedef struct {
  uint32_t req_id;
  uint32_t req_size; // Overall message size in bytes, including commands and payload
  uint8_t num;       // Number of valid entries in cmds[] (0 denotes a response message)
  command_t cmds[];  // Up to 255 command_t
} message_t;

const char* get_command_name(command_type_t cmd);

command_t* message_copy_tail(message_t *m, message_t *m_dst, command_t *cmd);
command_t* message_skip_cmds(message_t* m, command_t *cmd, int to_skip);

int cmd_type_size(command_type_t type);
command_t* cmd_next(command_t *c);
command_t* message_first_cmd(message_t *m);
const void msg_log(message_t* m, char* padding);


#endif

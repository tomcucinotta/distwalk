#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF_SIZE (16*1024*1024)

typedef enum { COMPUTE, STORE, LOAD, PSKIP, FORWARD, MULTI_FORWARD, REPLY } command_type_t;

typedef struct {
  uint32_t pkt_size;    // size of forwarded packet
  in_addr_t fwd_host;   // target IP of host to forward to (network encoding)
  uint16_t fwd_port;    // target port (network encoding, for multiple nodes on same host)
  uint32_t timeout;     // timeout in microsecond (0 means no timeout)
  uint8_t retries;      // how many times to reply before failing
  uint8_t on_fail_skip; // how many instructions skip after failing
} fwd_opts_t;

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
  int worker_id; // worker currently processing the message
  
  union {
    uint32_t     comp_time_us; // COMPUTE time (usecs)
    uint32_t     store_nbytes; // STORE data size
    uint32_t     load_nbytes;  // LOAD data size
    reply_opts_t resp;         // REPLY pkt size and concern
    fwd_opts_t   fwd;          // FORWARD host+port and pkt size
  } u;
} command_t;

// TODO: Here we need all quantities to be network-ordered
typedef struct {
  uint32_t req_id;
  uint32_t req_size; // Overall message size in bytes, including commands and payload
  uint8_t num;       // Number of valid entries in cmds[] (0 denotes a response message)
  command_t cmds[];  // Up to 255 command_t
} message_t;

static inline const char* get_command_name(command_type_t cmd) {
  switch (cmd) {
    case COMPUTE: return "COMPUTE";
    case STORE: return "STORE";
    case LOAD: return "LOAD";
    case PSKIP: return "SKIP";
    case FORWARD: return "FORWARD";
    case MULTI_FORWARD: return "MULTI_FORWARD";
    case REPLY: return "REPLY";
    default: 
      printf("Unknown command type\n");
      exit(EXIT_FAILURE);
  }
}

static inline const void msg_log(message_t* m, char* padding) {
  printf("%s", padding);
  printf("message (req_id: %u, req_size: %u, num: %u): ", m->req_id, m->req_size, m->num);
  
  for (int i=0; i<m->num; i++) {
    char opts[64] = "";

    switch (m->cmds[i].cmd) {
        case STORE:
            sprintf(opts, "%db", m->cmds[i].u.store_nbytes);
            break;
        case COMPUTE:
            sprintf(opts, "%dus", m->cmds[i].u.comp_time_us);
            break;
        case LOAD:
            sprintf(opts, "%db", m->cmds[i].u.load_nbytes);
            break;
        case MULTI_FORWARD:
        case FORWARD:
            sprintf(opts, "%s:%d,%u", inet_ntoa((struct in_addr) {m->cmds[i].u.fwd.fwd_host}), ntohs(m->cmds[i].u.fwd.fwd_port), m->cmds[i].u.fwd.pkt_size);
            break;
        case REPLY:
            sprintf(opts, "%db,%d", m->cmds[i].u.resp.resp_size, m->cmds[i].u.resp.n_ack);
            break;
        default: 
            printf("Unknown command type\n");
            exit(EXIT_FAILURE);
    }
    printf("%s(%s)%s", get_command_name(m->cmds[i].cmd), opts, i + 1 < m->num ? "->" : "");
  }

  printf("\n");
}
#endif

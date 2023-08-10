#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF_SIZE (16*1024*1024)

typedef enum { COMPUTE, STORE, LOAD, FORWARD, REPLY } command_type_t;

typedef struct {
  in_addr_t fwd_host;   // target IP of host to forward to (network encoding)
  uint16_t fwd_port;    // target port (network encoding, for multiple nodes on same host)
  uint32_t pkt_size;    // size of forwarded packet
} fwd_opts_t;

//TODO: consider whether to use this structs
/*typedef struct {
  uint64_t offset;
  uint32_t pkt_size;   // size of forwarded packet
} store_opts_t;

typedef struct {
  uint32_t pkt_size;    // size of forwarded packet
} reply_opts_t;*/

typedef struct {
  command_type_t cmd;
  union {
    uint32_t comp_time_us;  // COMPUTE time (usecs)
    uint32_t store_nbytes;  // STORE data size
    uint32_t load_nbytes;   // LOAD data size
    fwd_opts_t fwd;     // FORWARD host+port and pkt size
    //reply_opts_t reply;   // REPLY pkt size
  } u;
} command_t;

typedef struct {
  uint32_t req_id;
  uint32_t req_size;    // Overall message size in bytes, including commands and payload
  uint8_t num;      // Number of valid entries in cmds[]
  command_t cmds[]; // Up to 255 command_t
} message_t;

static inline const char* get_command_name(command_type_t cmd) {
  switch (cmd) {
    case COMPUTE: return "COMPUTE";
    case STORE: return "STORE";
    case LOAD: return "LOAD";
    case FORWARD: return "FORWARD";
    case REPLY: return "REPLY";
    default: 
      printf("Unknown command type\n");
      exit(EXIT_FAILURE);
  }
}

static inline const void msg_log(message_t* m) {
  for (int i=0; i<m->num; i++) {
    char opts[32] = "";
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
        case FORWARD:
            sprintf(opts, "%s:%d", inet_ntoa((struct in_addr) {m->cmds[i].u.fwd.fwd_host}), ntohs(m->cmds[i].u.fwd.fwd_port));
            break;
        case REPLY:
            sprintf(opts, "%dus", m->cmds[i].u.fwd.pkt_size);
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

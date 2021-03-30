#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#define BUF_SIZE (16*1024*1024)

typedef enum { COMPUTE, STORE, LOAD, FORWARD, REPLY } command_type_t;

const char* get_command_name(command_type_t cmd) {
  switch (cmd) {
    case COMPUTE: return "COMPUTE";
    case STORE: return "STORE";
    case LOAD: return "LOAD";
    case FORWARD: return "FORWARD";
    case REPLY: return "REPLY";
    default: 
      printf("Unknown command type\n");
      exit(-1);
  }
}

typedef struct {
  in_addr_t fwd_host;	// target IP of host to forward to
  uint16_t fwd_port;	// target port (for multiple nodes on same host)
  uint32_t pkt_size;	// size of forwarded packet
} fwd_opts_t;

//TODO: consider whether to use this structs
/*typedef struct {
  uint64_t offset;
  uint32_t pkt_size;   // size of forwarded packet
} store_opts_t;

typedef struct {
  uint32_t pkt_size;	// size of forwarded packet
} reply_opts_t;*/

typedef struct {
  command_type_t cmd;
  union {
    uint32_t comp_time_us;	// COMPUTE time (usecs)
    uint32_t store_nbytes;	// STORE data size
    uint32_t load_nbytes;	// LOAD data size
    fwd_opts_t fwd;		// FORWARD host+port and pkt size
    //reply_opts_t reply;	// REPLY pkt size
  } u;
} command_t;

typedef struct {
  uint32_t req_id;
  uint32_t req_size;	// Overall message size in bytes, including commands and payload
  uint8_t num;		// Number of valid entries in cmds[]
  command_t cmds[];	// Up to 255 command_t
} message_t;

#endif

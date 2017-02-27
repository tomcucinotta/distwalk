#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include <netinet/in.h>

typedef enum { COMPUTE, STORE, FORWARD } command_type_t;

typedef struct {
  in_addr_t fwd_host;	// target IP of host to forward to
  uint16_t fwd_port;	// target port (for multiple nodes on same host)
  uint32_t pkt_size;	// size of forwarded packet
} fwd_opts_t;

typedef struct {
  command_type_t cmd;
  union {
    uint16_t comp_time_us;	// COMPUTE time (usecs)
    uint16_t store_flags;	// STORE flags
    fwd_opts_t fwd;		// FORWARD host+port and pkt size
  } u;
} command_t;

typedef struct {
  uint32_t req_id;
  uint32_t req_size;	// Overall message size in bytes, including commands and payload
  uint8_t num;		// Number of valid entries in cmds[]
  command_t cmds[];	// Up to 255 command_t
} message_t;

#endif

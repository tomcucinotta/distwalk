#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include <netinet/in.h>

typedef enum { COMPUTE, STORE, FORWARD } command_type_t;

typedef struct {
  command_type_t cmd;
  union {
    uint16_t comp_time_us;	// COMPUTE time (usecs)
    uint16_t store_flags;	// STORE flags
    in_addr_t fwd_host;		// FORWARD host
  } u;
} command_t;

typedef struct {
  uint32_t req_id;
  uint32_t req_size;	// Overall message size in bytes, including commands and payload
  uint8_t num;		// Number of valid entries in cmds[]
  command_t cmds[64];	// Up to 64 command_t
} message_t;

#endif

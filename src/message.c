#include "message.h"

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

inline int cmd_size(command_t *c) {
  int base = sizeof(command_t);
  switch (c->cmd) {
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
  ptr += cmd_size(c);
  return (command_t*) ptr;
}

inline command_t* message_first_cmd(message_t *m) {
  return &m->cmds[0];
}

inline const void msg_log(message_t* m, char* padding) {
  printf("%s", padding);
  printf("message (req_id: %u, req_size: %u, num: %u): ", m->req_id, m->req_size, m->num);
  
  command_t *c = message_first_cmd(m), *pre_c;
  while(c->cmd != EOM) {
    char opts[64] = "";

    switch (c->cmd) {
        case STORE:
            sprintf(opts, "%db", cmd_get_opts(store_opts_t, c)->store_nbytes);
            break;
        case COMPUTE:
            sprintf(opts, "%dus", cmd_get_opts(comp_opts_t, c)->comp_time_us);
            break;
        case LOAD:
            sprintf(opts, "%db", cmd_get_opts(load_opts_t, c)->load_nbytes);
            break;
        case MULTI_FORWARD:
        case FORWARD:
            sprintf(opts, "%s:%d,%u", inet_ntoa((struct in_addr) {cmd_get_opts(fwd_opts_t, c)->fwd_host}), ntohs(cmd_get_opts(fwd_opts_t, c)->fwd_port), cmd_get_opts(fwd_opts_t, c)->pkt_size);
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
    printf("%s(%s)%s", get_command_name(pre_c->cmd), opts, c->cmd != EOM ? "->" : "");
  }

  printf(" [%ld bytes]\n", (unsigned char*)c - (unsigned char*)message_first_cmd(m));
}
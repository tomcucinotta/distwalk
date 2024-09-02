#ifndef __ADDRESS_UTILS_H__
#define __ADDRESS_UTILS_H__

#include <netinet/in.h>

#include "message.h"

#define MAX_HOSTPORT_STRLEN 31
#define DEFAULT_ADDR "127.0.0.1"
#define DEFAULT_PORT "7891"

void addr_parse(char* hostport_str, struct sockaddr_in* addr);
void addr_proto_parse(char* arg, char *nodehostport, proto_t *proto);

#endif /* __ADDRESS_UTILS_H__ */

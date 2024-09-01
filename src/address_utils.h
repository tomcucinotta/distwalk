#ifndef __ADDRESS_UTILS_H__
#define __ADDRESS_UTILS_H__

#include <netinet/in.h>

#define MAX_HOSTPORT_STRLEN 31
#define DEFAULT_ADDR "127.0.0.1"
#define DEFAULT_PORT "7891"


void addr_parse(char* hostport_str, struct sockaddr_in* addr);

#endif /* __ADDRESS_UTILS_H__ */
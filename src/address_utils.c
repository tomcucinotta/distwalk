#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "address_utils.h"
#include "dw_debug.h"

/**
 * @brief Configure settings of the server address struct.
 *        It supports "host[:port]" or ":port" syntax
 * 
 */
void addr_parse(char* hostport_str, struct sockaddr_in* addr) {
    char* hostname = DEFAULT_ADDR;
    int port = atoi(DEFAULT_PORT);
    char* port_str;

    check(strlen(hostport_str) > 0,
          "Allowed host/port syntaxes are \"host[:port]\" or \":port\"");

    // Get port
    port_str = strchr(hostport_str, ':');
    if (port_str) {
        dw_log("port_str: %s\n", port_str);
        *port_str = '\0';
        port_str++;

        // Convert port string to integer
        char* end_ptr = NULL;
        port = strtol(port_str, &end_ptr, 10);
        check(!*end_ptr, "Port '%s' is not a numeric value!\n", port_str);
    }

    // Now hostport_str containts hostname (or ip) only
    if (strlen(hostport_str) > 0)
        hostname = hostport_str;
    dw_log("hostport_str: %s\n", hostname);

    // Resolve hostname
    dw_log("Resolving %s...\n", hostname);
    struct hostent *e = gethostbyname(hostname);
    check(e != NULL);
    dw_log("Host %s resolved to %d bytes: %s\n", hostname, e->h_length,
           inet_ntoa(*(struct in_addr *)e->h_addr));

    // Build Internet address
    memset((char *) addr, '\0', sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    
    // Set IP address
    memmove((char *) &addr->sin_addr.s_addr, (char *)e->h_addr, e->h_length);
    
    // Set port number, using htons function to use proper byte order
    addr->sin_port = htons(port);

    //Set all bits of the padding field to 0
    memset(addr->sin_zero, '\0', sizeof(addr->sin_zero));

    if (port_str)
        // Restore original string (which was manipulated in-place)
        *(port_str - 1) = ':';
}
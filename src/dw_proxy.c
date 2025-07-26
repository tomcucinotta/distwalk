#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "address_utils.h"
#include "dw_debug.h"

typedef struct {
    pthread_t thr_sender;
    pthread_t thr_receiver;
    int fd_client;
    int fd_server;
} flow_t;

#define MAX_FLOWS 16
flow_t flows[MAX_FLOWS];
int n_flows = 0;

struct sockaddr_in bind_addr, dest_addr;

unsigned char buf_send[1024];
unsigned char buf_recv[1024];

unsigned long delay_us = 0;

// return 1 on success, 0 on failure
int do_connect(flow_t *p_flow) {
  p_flow->fd_server = socket(AF_INET, SOCK_STREAM, 0);
  check(p_flow->fd_server != -1);

  dw_log("Establishing connection to %s:%d ...\n",
         inet_ntoa(dest_addr.sin_addr), ntohs(dest_addr.sin_port));
  int rv = connect(p_flow->fd_server, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
  dw_log("connect() returned: %d\n", rv);
  return rv != -1;
}

void *receiver(void *arg) {
    flow_t *p_flow = (flow_t *) arg;
    int bytes_read;
    do {
        bytes_read = read(p_flow->fd_server, buf_recv, sizeof(buf_recv));
        if (bytes_read == -1) {
            perror("read() failed: ");
            exit(1);
        } else if (bytes_read > 0) {
            int to_write = bytes_read;
            do {
                int n = write(p_flow->fd_client, buf_recv + bytes_read - to_write, to_write);
                check (n >= 0);
                to_write -= n;
            } while (to_write > 0);
        }
    } while (bytes_read > 0);
    close(p_flow->fd_server);
    close(p_flow->fd_client);

    return NULL;
}

void *sender(void *arg) {
    flow_t *p_flow = (flow_t *) arg;
    usleep(delay_us);
    if (!do_connect(p_flow))
        return NULL;
    check(pthread_create(&p_flow->thr_receiver, NULL, receiver, (void*)p_flow) == 0);
    int bytes_read;
    do {
        bytes_read = read(p_flow->fd_client, buf_send, sizeof(buf_send));
        if (bytes_read == -1) {
            perror("read() failed: ");
            exit(1);
        } else if (bytes_read > 0) {
            usleep(delay_us);
            int to_write = bytes_read;
            do {
                int n = write(p_flow->fd_server, buf_send + bytes_read - to_write, to_write);
                check (n >= 0);
                to_write -= n;
            } while (to_write > 0);
        }
    } while (bytes_read > 0);
    close(p_flow->fd_server);
    close(p_flow->fd_client);
    pthread_join(p_flow->thr_receiver, NULL);

    return NULL;
}

int main(int argc, char *argv[]) {
    char *addr = strdup(DEFAULT_ADDR ":" DEFAULT_PORT);
    addr_parse(addr, &bind_addr);
    addr_parse(addr, &dest_addr);
    free(addr);
    argc--;  argv++;
    while (argc > 0) {
        if (strcmp(*argv, "-h") == 0 || strcmp(*argv, "--help") == 0) {
            printf("Usage: proxy [-b bindaddr[:port]] [--to connectaddr[:port]] [-d|--delay delay_ms]\n");
            exit(0);
        } else if (strcmp(*argv, "-b") == 0 || strcmp(*argv, "--bind") == 0) {
            argc--;  argv++;
            check(argc > 0);
            addr_parse(*argv, &bind_addr);
        } else if (strcmp(*argv, "--to") == 0) {
            argc--;  argv++;
            check(argc > 0);
            addr_parse(*argv, &dest_addr);
        } else if (strcmp(*argv, "-d") == 0 || strcmp(*argv, "--delay") == 0) {
            argc--;  argv++;
            check(argc > 0);
            delay_us = atol(*argv) * 1000;
        } else {
            fprintf(stderr, "Wrong option: %s\n", *argv);
            exit(1);
        }
        argc--;  argv++;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket() failed: ");
        exit(1);
    }
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(1);
    }
    if (bind(fd, (struct sockaddr *) &bind_addr, sizeof(bind_addr)) == -1) {
        perror("bind() failed: ");
        exit(1);
    }
    dw_log("Proxy bound to %s:%d\n",
           inet_ntoa(bind_addr.sin_addr), ntohs(bind_addr.sin_port));
    if (listen(fd, 5) == -1) {
        perror("listen() failed: ");
        exit(1);
    }
    while (1) {
        dw_log("Accepting new connections...\n");
        int new_fd = accept(fd, NULL, NULL);
        dw_log("accept() returned: %d\n", new_fd);
        if (new_fd == -1) {
            perror("accept() failed: ");
            exit(1);
        }

        check(n_flows < MAX_FLOWS);
        flow_t *p_flow = &flows[n_flows++];
        p_flow->fd_client = new_fd;
        check(pthread_create(&p_flow->thr_sender, NULL, sender, (void*)p_flow) == 0);
    }
}

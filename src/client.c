#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <stdlib.h>
#include <time.h>

#include <unistd.h>

#include <pthread.h>
#include <netdb.h>

#include "message.h"
#include "timespec.h"

#include "cw_debug.h"

#define check(cond) do {	 \
    int rv = (cond);		 \
    if (rv < 0) {		 \
      perror("Error: " #cond);	 \
      exit(-1);			 \
    }				 \
  } while (0)

void safe_send(int sock, unsigned char *buf, size_t len) {
  while (len > 0) {
    int sent;
    check(sent = send(sock, buf, len, 0));
    buf += sent;
    len -= sent;
  }
}

size_t safe_recv(int sock, unsigned char *buf, size_t len) {
  size_t read_tot = 0;
  while (len > 0) {
    int read;
    check(read = recv(sock, buf, len, 0));
    if (read == 0)
      break;
    buf += read;
    len -= read;
    read_tot += read;
  }
  return read_tot;
}

#define MAX_PKTS 1000000

clockid_t clk_id = CLOCK_REALTIME;
int clientSocket;
long usecs_send[MAX_PKTS];
long usecs_elapsed[MAX_PKTS];
// abs start-time of the experiment
struct timespec ts_start;
unsigned long num_pkts = 10;
unsigned long period_us = 1000;

void *thread_sender(void *data) {
  unsigned char send_buf[256];

  struct timespec ts_now;
  clock_gettime(clk_id, &ts_now);
  // Remember in ts_start the abs start time of the experiment
  ts_start = ts_now;

  for (int i = 0; i < num_pkts; i++) {
    /* remember time of send relative to ts_start */
    struct timespec ts_send;
    clock_gettime(clk_id, &ts_send);
    usecs_send[i] = ts_sub_us(ts_send, ts_start);
    /*---- Issue a request to the server ---*/
    message_t *m = (message_t *) send_buf;
    m->req_id = i;
    m->req_size = sizeof(send_buf);
    m->num = 1;
    m->cmds[0].cmd = COMPUTE;
    m->cmds[0].u.comp_time_us = 1;
    cw_log("Sending %u bytes...\n", m->req_size);
    safe_send(clientSocket, send_buf, m->req_size);
    struct timespec ts_delta = (struct timespec) { period_us / 1000000, (period_us % 1000000) * 1000 };
    ts_now = ts_add(ts_now, ts_delta);

    check(clock_nanosleep(clk_id, TIMER_ABSTIME, &ts_now, NULL));
  }

  return 0;
}

void *thread_receiver(void *data) {
  unsigned char recv_buf[256];
  for (int i = 0; i < num_pkts; i++) {
    /*---- Read the message from the server into the buffer ----*/
    safe_recv(clientSocket, recv_buf, 1);
    int pkt_id = recv_buf[0];
    struct timespec ts_now;
    clock_gettime(clk_id, &ts_now);
    unsigned long usecs = (ts_now.tv_sec - ts_start.tv_sec) * 1000000
      + (ts_now.tv_nsec - ts_start.tv_nsec) / 1000;
    usecs_elapsed[pkt_id] = usecs - usecs_send[pkt_id];
    cw_log("Data received: %02x (elapsed %ld us)\n", pkt_id, usecs_elapsed[pkt_id]);
  }

  for (int i = 0; i < num_pkts; i++) {
    printf("elapsed: %ld us\n", usecs_elapsed[i]);
  }

  return 0;
}

int main(int argc, char *argv[]) {
  char *hostname = "127.0.0.1";
  struct sockaddr_in serveraddr;
  socklen_t addr_size;

  argc--;  argv++;
  while (argc > 0) {
    if (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0) {
      printf("Usage: client [-h|--help] [-s hostname] [-c num_pkts] [-p period(us)]\n");
      exit(0);
    } else if (strcmp(argv[0], "-s") == 0) {
      assert(argc >= 2);
      hostname = argv[1];
      argc--;  argv++;
    } else if (strcmp(argv[0], "-c") == 0) {
      assert(argc >= 2);
      num_pkts = atoi(argv[1]);
      assert(num_pkts <= MAX_PKTS);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-p") == 0) {
      assert(argc >= 2);
      period_us = atol(argv[1]);
      argc--;  argv++;
    } else {
      printf("Unrecognized option: %s\n", argv[0]);
      exit(-1);
    }
    argc--;  argv++;
  }

  printf("Configuration: hostname=%s num_pkts=%lu period_us=%lu\n", hostname, num_pkts, period_us);

  cw_log("Resolving %s...\n", hostname);
  struct hostent *e = gethostbyname(hostname);
  check(e != NULL);

  /* build the server's Internet address */
  bzero((char *) &serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  bcopy((char *)e->h_addr, 
	(char *)&serveraddr.sin_addr.s_addr, e->h_length);
  serveraddr.sin_port = htons(7891);

  cw_log("Host %s resolved to %d bytes: %s\n", hostname, e->h_length, inet_ntoa(serveraddr.sin_addr));

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  clientSocket = socket(PF_INET, SOCK_STREAM, 0);

  int val = 0;
  setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (void *)&val, sizeof(val));

  /*---- Connect the socket to the server using the address struct ----*/
  addr_size = sizeof(serveraddr);
  check(connect(clientSocket, (struct sockaddr *) &serveraddr, addr_size));

  pthread_t sender;
  pthread_create(&sender, NULL, thread_sender, (void *) 0);

  pthread_t receiver;
  pthread_create(&receiver, NULL, thread_receiver, NULL);

  int rv;
  pthread_join(sender, (void **) &rv);
  pthread_join(receiver, (void **) &rv);

  return 0;
}

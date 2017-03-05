#include "message.h"
#include "timespec.h"
#include "cw_debug.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <errno.h>

#include <pthread.h>
#include <sys/epoll.h>

typedef struct {
  unsigned char *buf;		// NULL for unused buf_info
  unsigned long buf_size;
  unsigned char *curr_buf;
  unsigned long curr_size;
  int sock;
} buf_info;

#define MAX_BUFFERS 16
#define BUF_SIZE 4096

buf_info bufs[MAX_BUFFERS];

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
      return read_tot;
    buf += read;
    len -= read;
    read_tot += read;
  }
  return read_tot;
}

size_t recv_message(int sock, unsigned char *buf, size_t len) {
  assert(len >= 8);
  size_t read = safe_recv(sock, buf, 8);
  if (read == 0)
    return read;
  message_t *m = (message_t *) buf;
  assert(len >= m->req_size - 8);
  assert(safe_recv(sock, buf + 8, m->req_size - 8) == m->req_size - 8);
  return m->req_size;
}

void compute_for(unsigned long usecs) {
  struct timespec ts_beg, ts_end;
  cw_log("Computing for %lu usecs\n", usecs);
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_beg);
  do {
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_end);
  } while (ts_sub_us(ts_end, ts_beg) < usecs);
}

void process_messages(int sock, int buf_id) {
  size_t received = recv(sock, bufs[buf_id].curr_buf, bufs[buf_id].curr_size, 0);
  cw_log("recv() returned: %d\n", (int)received);
  if (received == 0) {
    cw_log("Connection closed by remote end\n");
    // EPOLL_CTL_DEL ?
    close(sock);
    free(bufs[buf_id].buf);
    bufs[buf_id].buf = NULL;
    return;
  } else if (received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    cw_log("Got EAGAIN or EWOULDBLOCK, ignoring...\n");
    return;
  } else if (received == -1) {
    perror("Unexpected error!");
    exit(-1);
  }
  bufs[buf_id].curr_buf += received;
  bufs[buf_id].curr_size -= received;

  unsigned char *buf = bufs[buf_id].buf;
  unsigned long msg_size = bufs[buf_id].curr_buf - buf;
  // batch processing of multiple messages, if received more than 1
  do {
    if (msg_size < 8) {
      cw_log("Got incomplete header, need to recv() more...\n");
      break;
    }
    message_t *m = (message_t *) buf;
    cw_log("Received %lu bytes, req_id=%u, req_size=%u, num=%d\n", msg_size, m->req_id, m->req_size, m->num);
    if (msg_size < m->req_size) {
      cw_log("Got header but incomplete message, need to recv() more...\n");
      break;
    }
    if (m->num >= 1) {
      if (m->cmds[0].cmd == COMPUTE) {
	compute_for(m->cmds[0].u.comp_time_us);
      }
    }
    cw_log("Sending back %lu\n", m->req_id);
    safe_send(sock, buf, sizeof(message_t));

    // move to batch processing of next message if any
    buf += m->req_size;
    msg_size = bufs[buf_id].curr_buf - buf;
    if (msg_size > 0)
      cw_log("Repeating loop with msg_size=%lu\n", msg_size);
  } while (msg_size > 0);

  if (buf == bufs[buf_id].curr_buf) {
    // all received data was processed, reset curr_* for next receive
    bufs[buf_id].curr_buf = bufs[buf_id].buf;
    bufs[buf_id].curr_size = bufs[buf_id].buf_size;
  } else {
    // leftover received data, move it to beginning of buf
    // TODO do this only if we're beyond a threshold in buf[]
    memmove(bufs[buf_id].buf, buf, bufs[buf_id].curr_buf - buf);
    bufs[buf_id].curr_buf = bufs[buf_id].buf;
    bufs[buf_id].curr_size = bufs[buf_id].buf_size - (bufs[buf_id].curr_buf - bufs[buf_id].buf);
  }
}

void *receive_thread(void *data) {
  int sock = (int)(long) data;
  unsigned char buf[1024];

  while (1) {
    size_t msg_size = recv_message(sock, buf, sizeof(buf));
    if (msg_size == 0) {
      cw_log("Connection closed by remote end\n");
      break;
    }
    message_t *m = (message_t *) buf;
    cw_log("Received %lu bytes, req_id=%u, req_size=%u, num=%d\n", msg_size, m->req_id, m->req_size, m->num);
    if (m->num >= 1) {
      if (m->cmds[0].cmd == COMPUTE) {
	compute_for(m->cmds[0].u.comp_time_us);
      }
    }
    safe_send(sock, buf, sizeof(message_t));
  }
  check(close(sock));
  return 0;
}

void setnonblocking(int fd) {
   int flags = fcntl(fd, F_GETFL, 0);
   assert(flags >= 0);
   flags |= O_NONBLOCK;
   assert(fcntl(fd, F_SETFL, flags) == 0);
}

#define MAX_EVENTS 10
void epoll_main_loop(int listen_sock) {
  struct epoll_event ev, events[MAX_EVENTS];
  int epollfd;

  /* Code to set up listening socket, 'listen_sock',
     (socket(), bind(), listen()) omitted */

  epollfd = epoll_create1(0);
  if (epollfd == -1) {
    perror("epoll_create1");
    exit(EXIT_FAILURE);
  }

  ev.events = EPOLLIN;
  ev.data.fd = -1;	// Special value denoting listen_sock
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1) {
    perror("epoll_ctl: listen_sock");
    exit(EXIT_FAILURE);
  }

  for (;;) {
    int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == -1) {
	struct sockaddr_in addr;
	socklen_t addr_size = sizeof(addr);
	int conn_sock = accept(listen_sock,
			   (struct sockaddr *) &addr, &addr_size);
	if (conn_sock == -1) {
	  perror("accept");
	  exit(EXIT_FAILURE);
	}
	// TODO: add the IP/port into a map to allow FORWARD finding the
	// already set-up socket
	cw_log("Accepted connection from: %s:%d\n", inet_ntoa(addr.sin_addr), addr.sin_port);
	setnonblocking(conn_sock);
	int buf_id;
	for (buf_id = 0; buf_id < MAX_BUFFERS; buf_id++)
	  if (bufs[buf_id].buf == 0)
	    break;
	if (buf_id == MAX_BUFFERS) {
	  fprintf(stderr, "Not enough buffers for new connection, closing!\n");
	  close(conn_sock);
	  continue;
	}
	bufs[buf_id].buf = malloc(BUF_SIZE);
	if (bufs[buf_id].buf == 0) {
	  fprintf(stderr, "Not enough memory for allocating new buffer, closing!\n");
	  close(conn_sock);
	  continue;
	}
	bufs[buf_id].buf_size = BUF_SIZE;
	bufs[buf_id].curr_buf = bufs[buf_id].buf;
	bufs[buf_id].curr_size = BUF_SIZE;
	bufs[buf_id].sock = conn_sock;

	ev.events = EPOLLIN | EPOLLET;
	// Use the data.u32 field to store the buf_id in bufs[]
	ev.data.u32 = buf_id;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock,
		      &ev) == -1) {
	  perror("epoll_ctl: conn_sock");
	  exit(EXIT_FAILURE);
	}
      } else {
	// FIXME - allow for receiving only message parts, handle EAGAIN
	int buf_id = events[i].data.u32;
	cw_log("Receiving and processing on buf_id=%d...\n", buf_id);
	process_messages(bufs[buf_id].sock, buf_id);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  int welcomeSocket;
  struct sockaddr_in serverAddr;

  // Tag all buf_info as unused
  for (int i = 0; i < MAX_BUFFERS; i++) {
    bufs[i].buf = 0;
  }

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  welcomeSocket = socket(PF_INET, SOCK_STREAM, 0);

  int i = 0;
  setsockopt(welcomeSocket, IPPROTO_TCP, SO_REUSEADDR, (void *)&i, sizeof(i));

  /*---- Configure settings of the server address struct ----*/
  /* Address family = Internet */
  serverAddr.sin_family = AF_INET;
  /* Set port number, using htons function to use proper byte order */
  serverAddr.sin_port = htons(7891);
  /* Set IP address to localhost */
  serverAddr.sin_addr.s_addr = inet_addr("0.0.0.0");
  /* Set all bits of the padding field to 0 */
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  /*---- Bind the address struct to the socket ----*/
  check(bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)));

  /*---- Listen on the socket, with 5 max connection requests queued ----*/
  check(listen(welcomeSocket, 5));
  cw_log("Accepting new connections...\n");

  epoll_main_loop(welcomeSocket);

  return 0;
}

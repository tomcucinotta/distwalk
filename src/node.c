#define _GNU_SOURCE
#include "message.h"
#include "timespec.h"
#include "cw_debug.h"

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <string.h>
#include <assert.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <errno.h>

#include <pthread.h>
#include <sys/epoll.h>

#define MAX_EVENTS 10

typedef enum { RECEIVING, SENDING, LOADING, STORING, CONNECTING } req_status;

typedef struct {
  unsigned char *buf;		// NULL for unused buf_info
  unsigned long buf_size;
  unsigned char *curr_buf;
  unsigned long curr_size;

  unsigned char *reply_buf;
  unsigned char *fwd_buf;

  unsigned char *store_buf;

  int sock;
  req_status status;
  int orig_sock_id;             // ID in socks[]
  pthread_mutex_t mtx;
} buf_info;

typedef struct {
  int epollfd;
  struct epoll_event events[MAX_EVENTS];
  int terminationfd; //special eventfd to handle termination
} thread_info;


static volatile int node_running = 1; //epoll_main_loop flag

#define MAX_BUFFERS 16

buf_info bufs[MAX_BUFFERS];
pthread_t workers[MAX_BUFFERS];
thread_info thread_infos[MAX_BUFFERS];

typedef struct {
  in_addr_t inaddr;	// target IP
  uint16_t port;	// target port (for multiple nodes on same host)
  int sock;		// socket handling messages from/to inaddr:port (0=unused)
} sock_info;

#define MAX_SOCKETS 16
sock_info socks[MAX_SOCKETS];
pthread_mutex_t socks_mtx;

char *bind_name = "0.0.0.0";
int bind_port = 7891;

int no_delay = 1;

int use_odirect = 0;

int epollfd;

// return sock associated to inaddr:port
int sock_find_addr(in_addr_t inaddr, int port) {
  pthread_mutex_lock(&socks_mtx);

  for (int i = 0; i < MAX_SOCKETS; i++) {
    if (socks[i].inaddr == inaddr && socks[i].port == port) {
      pthread_mutex_unlock(&socks_mtx);
      return socks[i].sock;
    }
  }

  pthread_mutex_unlock(&socks_mtx);
  return -1;
}

// return index of sock in socks[]
int sock_find_sock(int sock) {
  assert(sock != -1);

  pthread_mutex_lock(&socks_mtx);
  for (int i = 0; i < MAX_SOCKETS; i++) {
    if (socks[i].sock == sock) {
      pthread_mutex_unlock(&socks_mtx);
      return i;
    }
  }

  pthread_mutex_unlock(&socks_mtx);
  return -1;
}

char* storage_path = NULL;
int storage_fd = -1;

void sigint_cleanup(int _) {
  (void)_; //to avoid unused var warnings
  node_running = 0;

  //terminate workers by sending a notificaiton
  //on their terminationfd
  for (int i = 0; i < MAX_BUFFERS; i++) {
    eventfd_write(thread_infos[i].terminationfd, 1);
  }
}

// add the IP/port into the socks[] map to allow FORWARD finding an
// already set-up socket, through sock_find()
// FIXME: bad complexity with many sockets
int sock_add(in_addr_t inaddr, int port, int sock) {
  pthread_mutex_lock(&socks_mtx);
  int sock_id = sock_find_addr(inaddr, port);
  if (sock_id != -1){
    pthread_mutex_unlock(&socks_mtx);
    return sock_id;
  }
  for (int i = 0; i < MAX_SOCKETS; i++) {
    if (socks[i].sock == -1) {
      socks[i].inaddr = inaddr;
      socks[i].port = port;
      socks[i].sock = sock;

      pthread_mutex_unlock(&socks_mtx);
      return i;
    }
  }

  pthread_mutex_unlock(&socks_mtx);
  return -1;
}

void sock_del_id(int id) {
  assert(id < MAX_SOCKETS);

  pthread_mutex_lock(&socks_mtx);
  cw_log("marking socks[%d] invalid\n", id);
  socks[id].sock = -1;
  pthread_mutex_unlock(&socks_mtx);
}

// make entry in socks[] associated to sock invalid, return entry ID if found or -1
int sock_del(int sock) {
  pthread_mutex_lock(&socks_mtx);
  int id = sock_find_sock(sock);

  if (id == -1){
    pthread_mutex_unlock(&socks_mtx);
    return -1;
  }
  sock_del_id(id);

  pthread_mutex_unlock(&socks_mtx);
  return id;
}

void safe_send(int sock, unsigned char *buf, size_t len) {
  while (len > 0) {
    int sent;
    sys_check(sent = send(sock, buf, len, 0));
    buf += sent;
    len -= sent;
  }
}

void safe_write(int fd, unsigned char *buf, size_t len) {
  while (len > 0) {
    int sent;
    sys_check(sent = write(fd, buf, len));
    buf += sent;
    len -= sent;
  }
}

size_t safe_recv(int sock, unsigned char *buf, size_t len) {
  size_t read_tot = 0;
  while (len > 0) {
    int read;
    sys_check(read = recv(sock, buf, len, 0));
    if (read == 0)
      return read_tot;
    buf += read;
    len -= read;
    read_tot += read;
  }
  return read_tot;
}

// Copy m header into m_dst, skipping the first cmd_id elems in m_dst->cmds[]
void copy_tail(message_t *m, message_t *m_dst, int cmd_id) {
  // copy message header
  *m_dst = *m;
  // left-shift m->cmds[] into m_dst->cmds[], removing m->cmds[cmd_id]
  for (int i = cmd_id; i < m->num; i++) {
    m_dst->cmds[i - cmd_id] = m->cmds[i];
  }
  m_dst->num = m->num - cmd_id;
}

// cmd_id is the index of the FORWARD item within m->cmds[] here, we
// remove the first (cmd_id+1) commands from cmds[], and forward the
// rest to the next hop
void forward(int buf_id, message_t *m, int cmd_id) {
  int sock = sock_find_addr(m->cmds[cmd_id].u.fwd.fwd_host, m->cmds[cmd_id].u.fwd.fwd_port);
  assert(sock != -1);
  message_t *m_dst = (message_t *) bufs[buf_id].fwd_buf;
  copy_tail(m, m_dst, cmd_id + 1);
  m_dst->req_size = m->cmds[cmd_id].u.fwd.pkt_size;
  cw_log("Forwarding req %u to %s:%d\n", m->req_id,
	 inet_ntoa((struct in_addr) { m->cmds[cmd_id].u.fwd.fwd_host }),
	 m->cmds[cmd_id].u.fwd.fwd_port);
  cw_log("  cmds[] has %d items, pkt_size is %u\n", m_dst->num, m_dst->req_size);
  // TODO: return to epoll loop to handle sending of long packets
  // (here I'm blocking the thread)
  safe_send(sock, bufs[buf_id].fwd_buf, m_dst->req_size);
}

void reply(int sock, int buf_id, message_t *m, int cmd_id) {
  message_t *m_dst = (message_t *) bufs[buf_id].reply_buf;

  copy_tail(m, m_dst, cmd_id + 1);
  m_dst->req_size = m->cmds[cmd_id].u.fwd.pkt_size;
  cw_log("Replying to req %u\n", m->req_id);
  cw_log("  cmds[] has %d items, pkt_size is %u\n", m_dst->num, m_dst->req_size);
  // TODO: return to epoll loop to handle sending of long packets
  // (here I'm blocking the thread)
  safe_send(sock, bufs[buf_id].reply_buf, m_dst->req_size);
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
  cw_log("COMPUTE: computing for %lu usecs\n", usecs);
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_beg);
  do {
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts_end);
  } while (ts_sub_us(ts_end, ts_beg) < usecs);
}

unsigned long blk_size = 0;

ssize_t store(int buf_id, size_t bytes) {
  //generate the data to be stored
  if (use_odirect)
    bytes = (bytes + blk_size - 1) / blk_size * blk_size;
  cw_log("STORE: storing %lu bytes\n", bytes);

  safe_write(storage_fd, bufs[buf_id].store_buf, bytes);
  fsync(storage_fd);

  return bytes;
}

ssize_t load(size_t bytes) {
  char* tmp = (char*) malloc(bytes + 1);
  ssize_t read;
  cw_log("LOAD: loading %lu bytes\n", bytes);

  sys_check(read = pread(storage_fd, tmp, bytes, 0));

  free(tmp);
  return read;
}

int close_and_forget(int epollfd, int sock) {
  cw_log("removing sock=%d from epollfd\n", sock);
  if (epoll_ctl(epollfd, EPOLL_CTL_DEL, sock, NULL) == -1) {
    perror("epoll_ctl: deleting socket");
    exit(EXIT_FAILURE);
  }
  cw_log("removing sock=%d from socks[]\n", sock);
  sock_del(sock);
  return close(sock);
}

int process_messages(int sock, int buf_id) {
  size_t received = recv(sock, bufs[buf_id].curr_buf, bufs[buf_id].curr_size, 0);
  cw_log("recv() returned: %d\n", (int)received);
  if (received == 0) {
    cw_log("Connection closed by remote end\n");
    free(bufs[buf_id].buf);
    free(bufs[buf_id].reply_buf);
    free(bufs[buf_id].fwd_buf);
    free(bufs[buf_id].store_buf);

    pthread_mutex_lock(&bufs[buf_id].mtx);
    bufs[buf_id].buf = NULL;
    bufs[buf_id].reply_buf = NULL;
    pthread_mutex_unlock(&bufs[buf_id].mtx);

    return 0;
  } else if (received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    cw_log("Got EAGAIN or EWOULDBLOCK, ignoring...\n");
    return 1;
  } else if (received == -1) {
    perror("Unexpected error!");
    exit(-1);
  }
  bufs[buf_id].curr_buf += received;
  bufs[buf_id].curr_size -= received;

  unsigned char *buf = bufs[buf_id].buf;
  unsigned long msg_size = bufs[buf_id].curr_buf - buf;

  ssize_t data = -1;

  // batch processing of multiple messages, if received more than 1
  do {
    cw_log("msg_size=%lu\n", msg_size);
    if (msg_size < sizeof(message_t)) {
      cw_log("Got incomplete header, need to recv() more...\n");
      break;
    }
    message_t *m = (message_t *) buf;
    cw_log("Received %lu bytes, req_id=%u, req_size=%u, num=%d\n", msg_size, m->req_id, m->req_size, m->num);
    if (msg_size < m->req_size) {
      cw_log("Got header but incomplete message, need to recv() more...\n");
      break;
    }
    assert(m->req_size >= sizeof(message_t) && m->req_size <= BUF_SIZE);
    for (int i = 0; i < m->num; i++) {
      if (m->cmds[i].cmd == COMPUTE) {
	compute_for(m->cmds[i].u.comp_time_us);
      } else if (m->cmds[i].cmd == FORWARD) {
	forward(buf_id, m, i);
	// rest of cmds[] are for next hop, not me
	break;
      } else if (m->cmds[i].cmd == REPLY) {
        //simulate data retrieve
	if (data >= 0) {
          m->cmds[i].u.fwd.pkt_size += data;
	  data = -1;
	}
	reply(sock, buf_id, m, i);
	// any further cmds[] for replied-to hop, not me
	break;
      } else if (m->cmds[i].cmd == STORE && storage_path) {
        store(buf_id, m->cmds[i].u.store_nbytes);
      } else if (m->cmds[i].cmd == LOAD && storage_path) {
        data = load(m->cmds[i].u.load_nbytes);
      } else {
	cw_log("Unknown cmd: %d\n", m->cmds[0].cmd);
	exit(-1);
      }
    }

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
    // leftover received data, move it to beginning of buf unless already there
    if (buf != bufs[buf_id].buf) {
      // TODO do this only if we're beyond a threshold in buf[]
      unsigned long leftover = bufs[buf_id].curr_buf - buf;
      cw_log("Moving %lu leftover bytes back to beginning of buf with buf_id %d",
	     leftover, buf_id);
      memmove(bufs[buf_id].buf, buf, leftover);
      bufs[buf_id].curr_buf = bufs[buf_id].buf + leftover;
      bufs[buf_id].curr_size = bufs[buf_id].buf_size - leftover;
    }
  }

  return 1;
}

void send_messages(int buf_id) {
  printf("send_messages()\n");
}

void finalize_conn(int buf_id) {
  printf("finalize_conn()\n");
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
  sys_check(close_and_forget(epollfd, sock));
  return 0;
}

void setnonblocking(int fd) {
   int flags = fcntl(fd, F_GETFL, 0);
   assert(flags >= 0);
   flags |= O_NONBLOCK;
   assert(fcntl(fd, F_SETFL, flags) == 0);
}

void* epoll_worker_loop(void* args) {
  thread_info* infos = (thread_info*) args;
  struct epoll_event ev;
  int worker_running = 1;

  // Add terminationfd
  ev.events = EPOLLIN;
  ev.data.fd = infos->terminationfd;
  sys_check(epoll_ctl(infos->epollfd, EPOLL_CTL_ADD, infos->terminationfd, &ev)); 

  while (worker_running) {
    int nfds = epoll_wait(infos->epollfd, infos->events, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("epoll_wait");

      if (errno == EINTR) {
        worker_running = 0;
      } else {
        exit(EXIT_FAILURE);
      }
    }

    for (int i = 0; i < nfds; i++) {
      if (infos->events[i].data.fd == infos->terminationfd) {
        worker_running = 0;
	break;
      } else {
        int buf_id = infos->events[i].data.u32;

        if ((infos->events[i].events | EPOLLIN) && bufs[buf_id].status == RECEIVING) {
          int ret = process_messages(bufs[buf_id].sock, buf_id);

	  if (!ret) {
            close_and_forget(infos->epollfd, bufs[buf_id].sock); 
	  }
        } 
        else if ((infos->events[i].events | EPOLLOUT) && bufs[buf_id].status == SENDING)
          send_messages(buf_id);
        else if ((infos->events[i].events | EPOLLOUT) && bufs[buf_id].status == CONNECTING)
          finalize_conn(buf_id);
        else {
          fprintf(stderr, "unexpected status: event=%d, %d\n", infos->events[i].events, bufs[buf_id].status);
          exit(EXIT_FAILURE);
	}
      }
    }
  }

  return (void*) 1;
}

void epoll_main_loop(int listen_sock) {
  struct epoll_event ev, events[MAX_EVENTS];
  
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

  while (node_running) {
    cw_log("epoll_wait()ing...\n");
    int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
        perror("epoll_wait");

	if (errno == EINTR) {
          node_running = 0;
	} else {
          exit(EXIT_FAILURE);
	}
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
	cw_log("Accepted connection from: %s:%d\n", inet_ntoa(addr.sin_addr), addr.sin_port);
	//setnonblocking(conn_sock);
	int val = 1;
	sys_check(setsockopt(conn_sock, IPPROTO_TCP, TCP_NODELAY, (void *)&val, sizeof(val)));

        int orig_sock_id = sock_add(addr.sin_addr.s_addr, addr.sin_port, conn_sock);
        check(orig_sock_id != -1);

        unsigned char *new_buf = 0;
        unsigned char *new_reply_buf = 0;
        unsigned char *new_fwd_buf = 0;
        unsigned char *new_store_buf = 0;

        new_buf = malloc(BUF_SIZE);
        new_reply_buf = malloc(BUF_SIZE);
        new_fwd_buf = malloc(BUF_SIZE);
	if (storage_path)
          new_store_buf = (use_odirect ? aligned_alloc(blk_size, BUF_SIZE + blk_size) : malloc(BUF_SIZE));

        if (new_buf == 0 || new_reply_buf == 0 || new_fwd_buf == 0 || (storage_path && new_store_buf == 0)) {
	  close_and_forget(epollfd, conn_sock);
          goto continue_free;
        }

	int buf_id;
	for (buf_id = 0; buf_id < MAX_BUFFERS; buf_id++) {
	  pthread_mutex_lock(&bufs[buf_id].mtx);
	  if (bufs[buf_id].buf == 0){
	    break; //unlock mutex above after mallocs
	  }
	  pthread_mutex_unlock(&bufs[buf_id].mtx);
	}
	if (buf_id == MAX_BUFFERS) {
	  fprintf(stderr, "Not enough buffers for new connection, closing!\n");
	  close_and_forget(epollfd, conn_sock);
	  goto continue_free;
	}
	bufs[buf_id].buf = new_buf;
	bufs[buf_id].reply_buf = new_reply_buf;
	bufs[buf_id].fwd_buf = new_fwd_buf;
	if (storage_path)
	  bufs[buf_id].store_buf = new_store_buf;

        pthread_mutex_unlock(&bufs[buf_id].mtx);
     	
	// From here, safe to assume that bufs[buf_id] is thread-safe
	cw_log("Connection assigned to worker %d\n", buf_id);
	bufs[buf_id].buf_size = BUF_SIZE;
	bufs[buf_id].curr_buf = bufs[buf_id].buf;
	bufs[buf_id].curr_size = BUF_SIZE;
	bufs[buf_id].sock = conn_sock;
        bufs[buf_id].status = RECEIVING;
        bufs[buf_id].orig_sock_id = orig_sock_id;
      
        ev.events = EPOLLIN | EPOLLOUT;
        // Use the data.u32 field to store the buf_id in bufs[]
        ev.data.u32 = buf_id;
        
	//add client fd to the worker epoll
	//(which, at this point, is already up and running)
        sys_check(epoll_ctl(thread_infos[buf_id].epollfd, EPOLL_CTL_ADD, conn_sock, &ev));

        continue;

      continue_free:

        if (new_buf)
          free(new_buf);
        if (new_reply_buf)
          free(new_reply_buf);
        if (new_fwd_buf)
          free(new_fwd_buf);
        if (storage_path && new_store_buf)
          free(new_store_buf);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  int welcomeSocket;
  struct sockaddr_in serverAddr;

  argc--;  argv++;
  while (argc > 0) {
    if (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0) {
      printf("Usage: node [-h|--help] [-b bindname] [-bp bindport] [-s|--storage path/to/storage/file] [--odirect]\n");
      exit(0);
    } else if (strcmp(argv[0], "-b") == 0) {
      assert(argc >= 2);
      bind_name = argv[1];
      argc--;  argv++;
    } else if (strcmp(argv[0], "-bp") == 0) {
      assert(argc >= 2);
      bind_port = atol(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-nd") == 0 || strcmp(argv[0], "--no-delay") == 0) { //not implemented
      assert(argc >= 2);
      no_delay = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-s") == 0 || strcmp(argv[0], "--storage") == 0) {
      assert(argc >= 2);
      storage_path = argv[1];
      argc--;  argv++; 
    } else if (strcmp(argv[0], "--odirect") == 0) {
      use_odirect = 1;
    } else {
      printf("Unrecognized option: %s\n", argv[0]);
      exit(-1);
    }
    argc--;  argv++;
  }

  //Setup SIGINT signal handler
  signal(SIGINT, sigint_cleanup);

  // Tag all buf_info as unused
  for (int i = 0; i < MAX_BUFFERS; i++) {
    bufs[i].buf = 0;
  }

  // Tag all sock_info as unused
  for (int i = 0; i < MAX_SOCKETS; i++) {
    socks[i].sock = -1;
  }
 
  // Init worker threads
  for (int i = 0; i < MAX_BUFFERS; i++) {
    thread_infos[i].terminationfd = eventfd(0, 0);  
    sys_check(thread_infos[i].epollfd = epoll_create1(0));
    sys_check(pthread_create(&workers[i], NULL, epoll_worker_loop, (void*) &thread_infos[i]));
  }

  // Init bufs mutexs
  for (int i = 0; i < MAX_BUFFERS; i++) {
    sys_check(pthread_mutex_init(&bufs[i].mtx, NULL));
  }

  // Init socks mutex
  //TODO: change sock_add and sock_dell's logic to avoid lock re-entrancy
  pthread_mutexattr_t attr;

  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE); 
  
  sys_check(pthread_mutex_init(&socks_mtx, &attr));

  // Open storage file, if any
  if (storage_path) {
    int flags = O_RDWR | O_CREAT | O_TRUNC;
    if (use_odirect)
      flags |= O_DIRECT;
    sys_check(storage_fd = open(storage_path, flags, S_IRUSR | S_IWUSR));
    struct stat s;
    sys_check(fstat(storage_fd, &s));
    blk_size = s.st_blksize;
    cw_log("blk_size = %lu\n", blk_size);
  }

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  welcomeSocket = socket(PF_INET, SOCK_STREAM, 0);

  int val = 1;
  setsockopt(welcomeSocket, IPPROTO_TCP, SO_REUSEADDR, (void *)&val, sizeof(val));
  setsockopt(welcomeSocket, IPPROTO_TCP, SO_REUSEPORT, (void *)&val, sizeof(val));

  /*---- Configure settings of the server address struct ----*/
  /* Address family = Internet */
  serverAddr.sin_family = AF_INET;
  /* Set port number, using htons function to use proper byte order */
  serverAddr.sin_port = htons(bind_port);
  /* Set IP address to localhost */
  serverAddr.sin_addr.s_addr = inet_addr(bind_name);
  /* Set all bits of the padding field to 0 */
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  /*---- Bind the address struct to the socket ----*/
  sys_check(bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)));

  /*---- Listen on the socket, with 5 max connection requests queued ----*/
  sys_check(listen(welcomeSocket, 5));
  cw_log("Accepting new connections...\n");

  epoll_main_loop(welcomeSocket);

  //Join worker threads
  for (int i = 0; i < MAX_BUFFERS; i++) {
    sys_check(pthread_join(workers[i], NULL));
    close(thread_infos[i].terminationfd);
  }

  // Init bufs mutexs
  for (int i = 0; i < MAX_BUFFERS; i++) {
    sys_check(pthread_mutex_destroy(&bufs[i].mtx));
  }

  sys_check(pthread_mutex_destroy(&socks_mtx));

  //termination clean-ups
  if (storage_fd >= 0) {
    close(storage_fd);
  }
  
  return 0;
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <pthread.h>
#include <netdb.h>

#include "message.h"
#include "timespec.h"

#include "cw_debug.h"
#include "expon.h"

int exp_arrivals = 0;
int wait_spinning = 0;
int server_port = 7891;
int bind_port = 0;

unsigned int n_store = 0; 		// Number of STORE requests
unsigned long store_nbytes = 10; 	// Number of bytes to be written to the server's storage

unsigned int n_load = 0;		// Number of LOAD requests
unsigned long load_nbytes = 10; 	// Number of bytes to be read from the server's storage 

unsigned int n_compute = 0;		// Number of COMPUTE requests
unsigned long comptimes_us = 100;	// defaults to 100us
int exp_comptimes = 0;

unsigned long pkt_size = 128;
int exp_pkt_size = 0;

unsigned long resp_size = 128;
int exp_resp_size = 0;

int no_delay = 1;

void safe_send(int sock, unsigned char *buf, size_t len) {
  while (len > 0) {
    int sent;
    sys_check(sent = send(sock, buf, len, 0));
    cw_log("Sent %d bytes.\n", sent);
    buf += sent;
    len -= sent;
  }
}

size_t safe_recv(int sock, unsigned char *buf, size_t len) {
  size_t read_tot = 0;
  while (len > 0) {
    int read;
    sys_check(read = recv(sock, buf, len, 0));
    cw_log("Read %d bytes\n", read);
    if (read == 0)
      break;
    buf += read;
    len -= read;
    read_tot += read;
  }
  return read_tot;
}

//Weighted probabilities of executing a COMPUTE/STORE/LOAD request
//(Used for randomly patterned messages)
int sum_w = 0;
int weights[3] = {0,0,0}; //0 compute, 1 store, 2 load

//Weighted command type picker
command_type_t pick_next_cmd() {
  int r = rand() % sum_w;
  int i = 0;

  while (r >= weights[i] && i < 3) {
     r -= weights[i];
     i++;
  }

  return (command_type_t) i;
}

#define TCPIP_HEADERS_SIZE 66
#define MIN_SEND_SIZE (sizeof(message_t) + 2*sizeof(command_t))
#define MIN_REPLY_SIZE sizeof(message_t)

uint32_t exp_packet_size(uint32_t avg, uint32_t min, uint32_t max, struct drand48_data* rnd_buf){
  /* The pkt_size in input does not consider header size but I need to take
  * that into account if I want to generate an exponential distribution.
  */
  uint32_t ret = lround(expon(1.0 / (avg+TCPIP_HEADERS_SIZE), rnd_buf));

  if (ret >= TCPIP_HEADERS_SIZE)
    ret -= TCPIP_HEADERS_SIZE;
  else
    ret = 0;

  if (ret < min)
    return min;
  else if (ret > max)
    return max;
  else
    return ret;
}

#define MAX_PKTS 1000000

clockid_t clk_id = CLOCK_REALTIME;
int clientSocket;
long usecs_send[MAX_PKTS];
long usecs_elapsed[MAX_PKTS];
// abs start-time of the experiment
struct timespec ts_start;
unsigned int rate = 1000;	// pkt/s rate (period is its inverse)

unsigned long num_pkts = 0;

unsigned int ramp_step_secs = 0;	// if non-zero, supersedes num_pkts
unsigned int ramp_delta_rate = 100;	// added to rate every ramp_secs
unsigned int ramp_num_steps = 10;	// number of ramp-up steps

char *hostname = "127.0.0.1";
char *bindname = "0.0.0.0";

void *thread_sender(void *data) {
  unsigned char *send_buf = malloc(BUF_SIZE);
  check(send_buf != NULL);
  struct timespec ts_now;
  struct drand48_data rnd_buf;

  clock_gettime(clk_id, &ts_now);
  srand48_r(time(NULL), &rnd_buf);

  // Remember in ts_start the abs start time of the experiment
  ts_start = ts_now;
  int rate_start = rate;

  for (int i = 0; i < num_pkts; i++) {
    /* remember time of send relative to ts_start */
    struct timespec ts_send;
    clock_gettime(clk_id, &ts_send);
    usecs_send[i] = ts_sub_us(ts_send, ts_start);
    /*---- Issue a request to the server ---*/
    message_t *m = (message_t *) send_buf;
    m->req_id = i;

    if (exp_pkt_size){
      m->req_size = exp_packet_size(pkt_size, MIN_SEND_SIZE, BUF_SIZE, &rnd_buf);
    } else{
      m->req_size = pkt_size;
    }

    m->num = 2;
    command_type_t next_cmd;

    if (sum_w > 0) { //weighted pick
      next_cmd = pick_next_cmd();
    } else { //request prioritY: COMPUTE>STORE>LOAD
      if (n_compute > 0) {
        n_compute--;
        next_cmd = COMPUTE;
      } else if (n_store > 0) {
        n_store--;
        next_cmd = STORE;
      } else if (n_load > 0) {
        n_load--;
        next_cmd = LOAD;
      } else { //COMPUTE by default
        next_cmd = COMPUTE;
      }
    }

    m->cmds[0].cmd = next_cmd;
    // TODO: trunc pkt/resp size to BUF_SIZE when using the --exp- variants.
    m->cmds[1].cmd = REPLY;

    if (m->cmds[0].cmd == COMPUTE) {
      if (exp_comptimes) {
        m->cmds[0].u.comp_time_us = lround(expon(1.0 / comptimes_us, &rnd_buf));
      } else {
        m->cmds[0].u.comp_time_us = comptimes_us;
      }
    } else if (m->cmds[0].cmd == STORE) {
      m->cmds[0].u.store_nbytes = store_nbytes;
      m->req_size += store_nbytes;
    } else if (m->cmds[0].cmd == LOAD ){
      m->cmds[0].u.load_nbytes = load_nbytes;
    } else {
      printf("Unexpected branch (2)\n");
      exit(-1);
    }

    if (exp_resp_size){
       m->cmds[1].u.fwd.pkt_size = exp_packet_size(resp_size, MIN_REPLY_SIZE, BUF_SIZE, &rnd_buf);
    } else {
      assert(resp_size <= BUF_SIZE);
      m->cmds[1].u.fwd.pkt_size = resp_size;
    }

    uint32_t return_bytes = m->cmds[1].u.fwd.pkt_size;
    if (m->cmds[0].cmd == LOAD) {
      return_bytes += load_nbytes;
    }

    cw_log("%s: sending %u bytes (will expect %u bytes in response)...\n", get_command_name(next_cmd), m->req_size,
	                                                                   return_bytes);
    assert(m->req_size <= BUF_SIZE);
    safe_send(clientSocket, send_buf, m->req_size);

    unsigned long period_us = 1000000 / rate;
    unsigned long period_ns;
    if (exp_arrivals) {
      period_ns = lround(expon(1.0 / period_us, &rnd_buf) * 1000.0);
    } else {
      period_ns = period_us * 1000;
    }
    struct timespec ts_delta = (struct timespec) { period_ns / 1000000000, period_ns % 1000000000 };

    ts_now = ts_add(ts_now, ts_delta);

    if (wait_spinning) {
      struct timespec ts;
      do {
	clock_gettime(clk_id, &ts);
      } while (ts_leq(ts, ts_now));
    } else {
      sys_check(clock_nanosleep(clk_id, TIMER_ABSTIME, &ts_now, NULL));
    }

    if (ramp_step_secs != 0) {
      int step = usecs_send[i] / 1000000 / ramp_step_secs;
      rate = rate_start + step * ramp_delta_rate;
      cw_log("rate: %d\n", rate);
    }
  }

  cw_log("Sender thread is over.\n");

  return 0;
}

void *thread_receiver(void *data) {
  unsigned char *recv_buf = malloc(BUF_SIZE);
  check(recv_buf != NULL);
  for (int i = 0; i < num_pkts; i++) {
    /*---- Read the message from the server into the buffer ----*/
    // TODO: support receive of variable reply-size requests
    cw_log("Receiving %lu bytes (header)\n", sizeof(message_t));
    unsigned long read = safe_recv(clientSocket, recv_buf, sizeof(message_t));
    assert(read == sizeof(message_t));
    message_t *m = (message_t *) recv_buf;
    unsigned long pkt_id = m->req_id;
    cw_log("Received %lu bytes, req_id=%lu, pkt_size=%u, ops=%d\n",
	   read, pkt_id, m->req_size, m->num);
    cw_log("Expecting further %lu bytes (total pkt_size %u bytes)\n",
	   m->req_size - read, m->req_size);
    assert(m->req_size >= sizeof(message_t));
    safe_recv(clientSocket, recv_buf + read, m->req_size - read);

    struct timespec ts_now;
    clock_gettime(clk_id, &ts_now);
    unsigned long usecs = (ts_now.tv_sec - ts_start.tv_sec) * 1000000
      + (ts_now.tv_nsec - ts_start.tv_nsec) / 1000;
    usecs_elapsed[pkt_id] = usecs - usecs_send[pkt_id];
    cw_log("req_id %lu elapsed %ld us\n", pkt_id, usecs_elapsed[pkt_id]);
  }

  for (int i = 0; i < num_pkts; i++) {
    printf("t: %ld us, elapsed: %ld us\n", usecs_send[i], usecs_elapsed[i]);
  }
  cw_log("receiver thread is over, closing socket\n");
  close(clientSocket);

  return 0;
}

int main(int argc, char *argv[]) {
  struct sockaddr_in serveraddr;
  socklen_t addr_size;

  argc--;  argv++;
  while (argc > 0) {
    if (strcmp(argv[0], "-h") == 0 || strcmp(argv[0], "--help") == 0) {
      printf("Usage: client [-h|--help] [-b bindname] [-bp bindport] [-sn servername] [-sb serverport] [-n num_pkts] [-c num_compute] [-s num_store] [-l num_load] [-p period(us)] [-r|--rate rate] [-ea|--exp-arrivals] [-rss|--ramp-step-secs secs] [-rdr|--ramp-delta-rate r] [-rns|--ramp-num-steps n] [-C|--comp-time comp_time(us)] [-S|--store-data n(bytes)] [-L|--load-data n(bytes)] [-Cw|--comp-weight n] [-Sw|--store-weight n] [-Lw|--load-weight n] [-ec|--exp-comp] [-ws|--wait-spin] [-ps req_size] [-eps|--exp-req-size] [-rs resp_size] [-ers|--exp-resp-size] [-nd|--no-delay val]\n");
      printf("Packet sizes are in bytes and do not consider headers added on lower network levels (TCP+IP+Ethernet = 66 bytes)\n");
      exit(0);
    } else if (strcmp(argv[0], "-sn") == 0) {
      assert(argc >= 2);
      hostname = argv[1];
      argc--;  argv++;
    } else if (strcmp(argv[0], "-sp") == 0) {
      assert(argc >= 2);
      server_port = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-b") == 0) {
      assert(argc >= 2);
      bindname = argv[1];
      argc--;  argv++;
    } else if (strcmp(argv[0], "-bp") == 0) {
      assert(argc >= 2);
      bind_port = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-n") == 0) {
      assert(argc >= 2);
      num_pkts = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-c") == 0) {
      assert(argc >= 2);
      n_compute = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-s") == 0) {
      assert(argc >= 2);
      n_store = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-l") == 0) {
      assert(argc >= 2);
      n_load = atoi(argv[1]);
      argc--;  argv++;
   } else if (strcmp(argv[0], "-p") == 0) {
      assert(argc >= 2);
      rate = 1000000 / atol(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-r") == 0 || strcmp(argv[0], "--rate") == 0) {
      assert(argc >= 2);
      rate = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-ea") == 0 || strcmp(argv[0], "--exp-arrivals") == 0) {
      exp_arrivals = 1;
    } else if (strcmp(argv[0], "-rdr") == 0 || strcmp(argv[0], "--ramp-delta-rate") == 0) {
      assert(argc >= 2);
      ramp_delta_rate = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-rns") == 0 || strcmp(argv[0], "--ramp-num-steps") == 0) {
      assert(argc >= 2);
      ramp_num_steps = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-rss") == 0 || strcmp(argv[0], "--ramp-step-secs") == 0) {
      assert(argc >= 2);
      ramp_step_secs = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-C") == 0 || strcmp(argv[0], "--comp-time") == 0) {
      assert(argc >= 2);
      comptimes_us = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-S") == 0 || strcmp(argv[0], "--store-data") == 0) {
      assert(argc >= 2);
      store_nbytes = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-L") == 0 || strcmp(argv[0], "--load-data") == 0) {
      assert(argc >= 2);
      load_nbytes = atoi(argv[1]);
      argc--;  argv++;
   } else if (strcmp(argv[0], "-Cw") == 0 || strcmp(argv[0], "--comp-weight") == 0) {
      assert(argc >= 2);
      weights[COMPUTE] = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-Sw") == 0 || strcmp(argv[0], "--store-weight") == 0) {
      assert(argc >= 2);
      weights[STORE] = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-Lw") == 0 || strcmp(argv[0], "--load-weight") == 0) {
      assert(argc >= 2);
      weights[LOAD] = atoi(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-ec") == 0 || strcmp(argv[0], "--exp-comp") == 0) {
      exp_comptimes = 1;
    } else if (strcmp(argv[0], "-ws") == 0 || strcmp(argv[0], "--waitspin") == 0) {
      wait_spinning = 1;
    } else if (strcmp(argv[0], "-ps") == 0 || strcmp(argv[0], "--pkt-size") == 0) {
      assert(argc >= 2);
      pkt_size = atol(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-eps") == 0 || strcmp(argv[0], "--exp-pkt-size") == 0) {
      exp_pkt_size = 1;
    } else if (strcmp(argv[0], "-rs") == 0 || strcmp(argv[0], "--resp-size") == 0) {
      assert(argc >= 2);
      resp_size = atol(argv[1]);
      argc--;  argv++;
    } else if (strcmp(argv[0], "-ers") == 0 || strcmp(argv[0], "--exp-resp-size") == 0) {
      exp_resp_size = 1;
    } else if (strcmp(argv[0], "-nd") == 0 || strcmp(argv[0], "--no-delay") == 0) {
      assert(argc >= 2);
      no_delay = atoi(argv[1]);
      argc--;  argv++;
    } else {
      printf("Unrecognized option: %s\n", argv[0]);
      exit(-1);
    }
    argc--;  argv++;
  }

  //globals
  for (int i = 0; i < 3; i++) {
    sum_w += weights[i];
  }

  //check input args consistency
  if (num_pkts == 0) { //-n option has not been used
    num_pkts = n_compute + n_store + n_load;
  } else {
    if (n_compute > 0 || n_store > 0 || n_load > 0) {
        assert(num_pkts == n_compute + n_store + n_load);
    }
  }
  assert(num_pkts <= MAX_PKTS);
  
  if (ramp_step_secs != 0) {
    num_pkts = 0;
    int r = rate;
    for (int s = 0; s < ramp_num_steps; s++) {
      num_pkts += r * ramp_step_secs;
      r += ramp_delta_rate;
    }
  }

  printf("Configuration:\n");
  printf("  bind=%s:%d\n", bindname, bind_port);
  printf("  hostname=%s:%d\n", hostname, server_port);
  printf("  num_pkts=%lu (COMPUTE:%d, STORE:%d, LOAD:%d)\n", num_pkts, n_compute, n_store, n_load);
  printf("  rate=%d, exp_arrivals=%d\n",
	 rate, exp_arrivals);
  printf("  waitspin=%d\n", wait_spinning);
  printf("  ramp_num_steps=%d, ramp_delta_rate=%d, ramp_step_secs=%d\n",
	 ramp_num_steps, ramp_delta_rate, ramp_step_secs);
  printf("  comptime_us=%lu, exp_comptimes=%d\n",
	 comptimes_us, exp_comptimes);
  printf("  pkt_size=%lu (%lu with headers), exp_pkt_size=%d\n",
	 pkt_size, pkt_size+TCPIP_HEADERS_SIZE, exp_pkt_size);
  printf("  resp_size=%lu (%lu with headers), exp_resp_size=%d\n",
	 resp_size, resp_size+TCPIP_HEADERS_SIZE, exp_resp_size);
  printf("  min packet size due to header: send=%lu, reply=%lu\n", MIN_SEND_SIZE, MIN_REPLY_SIZE);
  printf("  max packet size: %d\n", BUF_SIZE);
  printf("  no_delay: %d\n", no_delay);

  assert(pkt_size >= MIN_SEND_SIZE);
  assert(pkt_size <= BUF_SIZE);
  assert(resp_size >= MIN_REPLY_SIZE);
  assert(resp_size <= BUF_SIZE);
  assert(no_delay == 0 || no_delay == 1);

  //Init random number generator
  srand(time(NULL));

  cw_log("Resolving %s...\n", hostname);
  struct hostent *e = gethostbyname(hostname);
  check(e != NULL);
  cw_log("Host %s resolved to %d bytes: %s\n", hostname, e->h_length, inet_ntoa(*(struct in_addr *)e->h_addr));

  /* build the server's Internet address */
  bzero((char *) &serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  bcopy((char *)e->h_addr, 
	(char *)&serveraddr.sin_addr.s_addr, e->h_length);
  serveraddr.sin_port = htons(server_port);

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  clientSocket = socket(PF_INET, SOCK_STREAM, 0);

  sys_check(setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (void *)&no_delay, sizeof(no_delay)));

  cw_log("Resolving %s...\n", bindname);
  struct hostent *e2 = gethostbyname(bindname);
  check(e2 != NULL);
  cw_log("Host %s resolved to %d bytes: %s\n", bindname, e2->h_length, inet_ntoa(*(struct in_addr *)e2->h_addr));

  struct sockaddr_in myaddr;
  myaddr.sin_family = AF_INET;
  /* Set IP address to resolved bindname */
  bcopy((char *)e2->h_addr,
	(char *)&myaddr.sin_addr.s_addr, e2->h_length);
  /* Set port to zero, requesting allocation of any available ephemeral port */
  myaddr.sin_port = bind_port;
  /* Set all bits of the padding field to 0 */
  memset(myaddr.sin_zero, '\0', sizeof(myaddr.sin_zero));

  cw_log("Binding to %s:%d\n", inet_ntoa(myaddr.sin_addr), myaddr.sin_port);

  /*---- Bind the address struct to the socket ----*/
  sys_check(bind(clientSocket, (struct sockaddr *) &myaddr, sizeof(myaddr)));

  /*---- Connect the socket to the server using the address struct ----*/
  addr_size = sizeof(serveraddr);
  sys_check(connect(clientSocket, (struct sockaddr *) &serveraddr, addr_size));

  pthread_t receiver;
  assert(pthread_create(&receiver, NULL, thread_receiver, NULL) == 0);

  pthread_t sender;
  assert(pthread_create(&sender, NULL, thread_sender, NULL) == 0);

  pthread_join(sender, NULL);
  pthread_join(receiver, NULL);

  cw_log("Joined sender and receiver threads, exiting\n");

  return 0;
}

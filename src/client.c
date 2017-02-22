#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <stdlib.h>

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
    buf += read;
    len -= read;
    read_tot += len;
  }
  return read_tot;
}

int main(int argc, char *argv[]){
  int clientSocket;
  unsigned char req[1024];
  unsigned char ans[1024];
  struct sockaddr_in serverAddr;
  socklen_t addr_size;

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  clientSocket = socket(PF_INET, SOCK_STREAM, 0);
  
  /*---- Configure settings of the server address struct ----*/
  /* Address family = Internet */
  serverAddr.sin_family = AF_INET;
  /* Set port number, using htons function to use proper byte order */
  serverAddr.sin_port = htons(7891);
  /* Set IP address to localhost */
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  /* Set all bits of the padding field to 0 */
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  /*---- Connect the socket to the server using the address struct ----*/
  addr_size = sizeof serverAddr;
  assert(connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size) == 0);

  /*---- Issue a request to the server ---*/
  req[0] = 0xab;
  safe_send(clientSocket, req, 1);
  
  /*---- Read the message from the server into the buffer ----*/
  int read = safe_recv(clientSocket, ans, 1);

  /*---- Print the received message ----*/
  printf("Data received: %02x\n", ans[0]);   

  return 0;
}

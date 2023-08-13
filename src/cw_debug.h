#ifndef __CW_DEBUG_H__
#define __CW_DEBUG_H__

#include <stdio.h>
#include <unistd.h>

#ifdef CW_DEBUG

#define cw_log(msg, args...) do { \
    printf(msg, ##args);  \
    fflush(stdout);  \
  } while (0);

#else

#define cw_log(msg, args...)

#endif

// Exit immediately if the syscall call returns an error
#define sys_check(call) do {	 \
    int __rv = (call);		 \
    if (__rv < 0) {		 \
      perror("Error: " #call);	 \
      exit(EXIT_FAILURE);	 \
    }				 \
  } while (0)

// Exit immediately if cond is violated
#define check(cond) do {	 \
    if (!(cond)) {		 \
      fprintf(stderr, "Error: %s\n", #cond);     \
      exit(EXIT_FAILURE);	 \
    }				 \
  } while (0)

// Execute stmt if cond is violated
#define check_do(cond, stmt) do {		 \
    if (!(cond)) {				 \
      fprintf(stderr, "Error: %s\n", #cond);     \
      stmt;					 \
    }						 \
  } while (0)

// Dump error on stderr if cond is violated, and ignore
#define check_ignore(cond) do {			 \
    if (!(cond)) {				 \
      fprintf(stderr, "Error: %s\n", #cond);     \
    }						 \
  } while (0)

#endif

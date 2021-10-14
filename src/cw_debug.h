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
      exit(-1);			 \
    }				 \
  } while (0)

// Exit immediately if cond is violated
#define check(cond) do {	 \
    if (!(cond)) {		 \
      fprintf(stderr, "Error: " #cond);		\
      exit(-1);			 \
    }				 \
  } while (0)

// Ignore the syscall if cond is satisfied
#define eventually_ignore_sys(call, cond) do { \
	if (cond) { \
	  sys_check(call); \
	} \
  } while (0)

#endif

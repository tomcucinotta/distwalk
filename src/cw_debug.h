#ifndef __CW_DEBUG_H__
#define __CW_DEBUG_H__

#include <stdio.h>
#include <unistd.h>

#ifdef CW_DEBUG

#define cw_log(msg, args...) do { \
    printf(msg, ##args);  \
  } while (0);

#else

#define cw_log(msg, args...)

#endif

// Exit immediately if cond is violated
#define check(cond) do {	 \
    int __rv = (cond);		 \
    if (__rv < 0) {		 \
      perror("Error: " #cond);	 \
      exit(-1);			 \
    }				 \
  } while (0)

#endif

#ifndef __DW_DEBUG_H__
#define __DW_DEBUG_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/prctl.h>

// a weak global variable is ignored when a strong one is detected.
// This is needed for the edge-cases where thread_name is not defined,
// (e.g. dw_debug is used for unit testing, and not via dw_{client,node})
__attribute__((weak)) __thread char thread_name[16];

#ifdef DW_DEBUG 
#define dw_log(msg, ...) do { \
    struct timespec __ts; \
    clock_gettime(CLOCK_MONOTONIC, &__ts);\
    if (thread_name) \
      printf("[%ld.%09ld][%s][%s:%d] " msg, __ts.tv_sec, __ts.tv_nsec, thread_name, __FILE__, __LINE__, ## __VA_ARGS__); \
    else \
      printf("[%ld.%09ld][%s:%d] " msg, __ts.tv_sec, __ts.tv_nsec, __FILE__, __LINE__, ## __VA_ARGS__); \
    fflush(stdout);  \
  } while (0);

#else

#define dw_log(msg, ...)

#endif

// Exit immediately if the syscall call returns an error
#define sys_check(call) do {	 \
    int __rv = (call);		 \
    if (__rv < 0) {		 \
      fprintf(stderr, "Error: %s: %s [%s:%d]\n", #call, strerror(errno), __FILE__, __LINE__);	 \
      exit(EXIT_FAILURE);	 \
    }				 \
  } while (0)

// Exit immediately if cond is violated
#define check(cond, ...) do {	 \
    if (!(cond)) {		 \
      fprintf(stderr, "Error:" #cond ": " __VA_ARGS__);       \
      fprintf(stderr, " [%s:%d]\n", __FILE__, __LINE__);     \
      exit(EXIT_FAILURE);	 \
    }				 \
  } while (0)

// Execute stmt if cond is violated
#define check_do(cond, stmt) do {		 \
    if (!(cond)) {				 \
      fprintf(stderr, "Error: %s [%s:%d]\n", #cond, __FILE__, __LINE__);     \
      stmt;					 \
    }						 \
  } while (0)

// Dump error on stderr if cond is violated, and ignore
#define check_ignore(cond) do {			 \
    if (!(cond)) {				 \
      fprintf(stderr, "Error: %s [%s:%d]\n", #cond, __FILE__, __LINE__);     \
    }						 \
  } while (0)

// Execute a test function
#define perform_test(fun) ({                     \
    int __rv = (fun);                            \
    printf("TEST " #fun ": ");                   \
    if (__rv)                                    \
        printf("SUCCESS\n");                     \
    else                                         \
        printf("FAILED\n");                      \
    __rv;                                        \
  })

#endif /* __DW_DEBUG_H__ */

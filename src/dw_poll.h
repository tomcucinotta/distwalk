#ifndef __DW_POLL_H__
#define __DW_POLL_H__

#include <sys/select.h>
#include <sys/epoll.h>
#include <poll.h>

typedef enum { DW_SELECT, DW_POLL, DW_EPOLL } dw_poll_type_t;

// these flags are OR-ed both in input and output to dw_poll_*()
typedef enum { DW_POLL_IN=1, DW_POLL_OUT=2, DW_POLL_1SHOT=4, DW_POLL_ERR=8 } dw_poll_flags;

#define MAX_POLLFD 8192
#define MAX_POLL_EVENTS 16

typedef struct {
    dw_poll_type_t poll_type;
    union {
        struct {
            int rd_fd[MAX_POLLFD];
            int wr_fd[MAX_POLLFD];
            uint64_t rd_aux[MAX_POLLFD];
            uint64_t wr_aux[MAX_POLLFD];
            dw_poll_flags rd_flags[MAX_POLLFD];
            dw_poll_flags wr_flags[MAX_POLLFD];
            int n_rd_fd;
            int n_wr_fd;
            fd_set rd_fds, wr_fds, ex_fds;
            int iter;   // from 0 to n_rd_fd + n_wr_fd - 1
        } select_fds;
        struct {
            struct pollfd pollfds[MAX_POLLFD];
            uint64_t aux[MAX_POLLFD];
            dw_poll_flags flags[MAX_POLLFD];
            int n_pollfds;
            int iter;
        } poll_fds;
        struct {
            struct epoll_event events[MAX_POLLFD];
            int epollfd;
            int n_events;
            int iter;
        } epoll_fds;
    } u;
} dw_poll_t;

// initialize the list of monitored fds
int dw_poll_init(dw_poll_t *p_poll, dw_poll_type_t type);

// add fd to the list of monitored fds, with associated custom data aux
int dw_poll_add(dw_poll_t *p_poll, int fd, dw_poll_flags flags, uint64_t aux);

// modify fd in the list of monitored fds
// use rd == wr == 0 to delete fd from the list of monitored fds
int dw_poll_mod(dw_poll_t *p_poll, int fd, dw_poll_flags flags, uint64_t aux);

// remove fd from the list of monitored fds
static inline int dw_poll_del(dw_poll_t *p_poll, int fd) {
    return dw_poll_mod(p_poll, fd, 0, 0);
}

// block waiting for any fd to have an event
int dw_poll_wait(dw_poll_t *p_poll);

// after a successful return of dw_poll_wait(), return the next fd,
// its associated events in *p_rd/*p_wr, and custom data in *p_aux,
// or return 0 if there are no more fds
int dw_poll_next(dw_poll_t *p_poll, dw_poll_flags *p_flags, uint64_t *p_aux);

#endif /* __DW_POLL_H__ */

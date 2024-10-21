#ifndef __DW_POLL_H__
#define __DW_POLL_H__

#include <sys/select.h>
#include <sys/epoll.h>
#include <poll.h>

typedef enum { DW_SELECT, DW_POLL, DW_EPOLL } dw_poll_type_t;

#define MAX_POLLFD 8192
#define MAX_POLL_EVENTS 16

typedef struct {
    dw_poll_type_t poll_type;
    union {
        struct {
            int rd_fd[MAX_POLLFD];
            int wr_fd[MAX_POLLFD];
            int n_rd_fd;
            int n_wr_fd;
            fd_set rd_fds, wr_fds, ex_fds;
            int max_fd; // needed for select()
            int iter;   // from 0 to n_rd_fd + n_wr_fd - 1
        } select_fds;
        struct {
            struct pollfd pollfds[MAX_POLLFD];
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

int dw_poll_init(dw_poll_t *p_poll, dw_poll_type_t type);
int dw_poll_add(dw_poll_t *p_poll, int fd, int rd, int wr);
int dw_poll_del(dw_poll_t *p_poll, int fd, int rd, int wr);
int dw_poll_wait(dw_poll_t *p_poll);
int dw_poll_next(dw_poll_t *p_poll, int *rd, int *wr);

#endif /* __DW_POLL_H__ */

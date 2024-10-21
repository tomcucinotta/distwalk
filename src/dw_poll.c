#include "dw_poll.h"
#include "dw_debug.h"

// return value useful to return failure if we allocate memory here in the future
int dw_poll_init(dw_poll_t *p_poll, dw_poll_type_t type) {
    p_poll->poll_type = type;
    switch (p_poll->poll_type) {
    case DW_SELECT:
        p_poll->u.select_fds.n_rd_fd = 0;
        p_poll->u.select_fds.n_wr_fd = 0;
        break;
    case DW_POLL:
        p_poll->u.poll_fds.n_pollfds = 0;
        break;
    case DW_EPOLL:
        sys_check(p_poll->u.epoll_fds.epollfd = epoll_create1(0));
        break;
    default:
        check(0, "Wrong dw_poll_type");
    }
    return 0;
}

int dw_poll_add(dw_poll_t *p_poll, int fd, int rd, int wr, uint64_t aux) {
    int rv = 0;
    switch (p_poll->poll_type) {
    case DW_SELECT:
        if ((rd && p_poll->u.select_fds.n_rd_fd == MAX_POLLFD)
            || (wr && p_poll->u.select_fds.n_wr_fd == MAX_POLLFD)) {
            dw_log("Exhausted number of possible fds in select()\n");
            return -1;
        }
        if (rd) {
            p_poll->u.select_fds.rd_fd[p_poll->u.select_fds.n_rd_fd] = fd;
            p_poll->u.select_fds.rd_aux[p_poll->u.select_fds.n_rd_fd] = aux;
            p_poll->u.select_fds.n_rd_fd++;
        }
        if (wr) {
            p_poll->u.select_fds.wr_fd[p_poll->u.select_fds.n_wr_fd] = fd;
            p_poll->u.select_fds.wr_aux[p_poll->u.select_fds.n_wr_fd] = aux;
            p_poll->u.select_fds.n_wr_fd++;
        }
        break;
    case DW_POLL:
        if (p_poll->u.poll_fds.n_pollfds == MAX_POLLFD) {
            dw_log("Exhausted number of possible fds in poll()\n");
            return -1;
        }
        struct pollfd *pev = &p_poll->u.poll_fds.pollfds[p_poll->u.poll_fds.n_pollfds];
        p_poll->u.poll_fds.aux[p_poll->u.poll_fds.n_pollfds] = aux;
        p_poll->u.poll_fds.n_pollfds++;
        pev->fd = fd;
        pev->events = 0;
        if (rd)
            pev->events |= POLLIN;
        if (wr)
            pev->events |= POLLOUT;
        break;
    case DW_EPOLL:
        struct epoll_event ev = (struct epoll_event) {
            .data.u64 = aux,
            .events = (rd ? EPOLLIN : 0) | (wr ? EPOLLOUT : 0),
        };
        rv = epoll_ctl(p_poll->u.epoll_fds.epollfd, EPOLL_CTL_ADD, fd, &ev);
        break;
    default:
        check(0, "Wrong dw_poll_type");
    }
    return rv;
}

int dw_poll_mod(dw_poll_t *p_poll, int fd, int rd, int wr, uint64_t aux) {
    int rv = 0;
    switch (p_poll->poll_type) {
    case DW_SELECT:
        if (rd)
            for (int i = 0; i < p_poll->u.select_fds.n_rd_fd; i++)
                if (p_poll->u.select_fds.rd_fd[i] == fd) {
                    p_poll->u.select_fds.n_rd_fd--;
                    p_poll->u.select_fds.rd_fd[i] =
                        p_poll->u.select_fds.rd_fd[p_poll->u.select_fds.n_rd_fd];
                    p_poll->u.select_fds.rd_aux[i] =
                        p_poll->u.select_fds.rd_aux[p_poll->u.select_fds.n_rd_fd];
                    break;
                }
        if (wr)
            for (int i = 0; i < p_poll->u.select_fds.n_wr_fd; i++)
                if (p_poll->u.select_fds.wr_fd[i] == fd) {
                    p_poll->u.select_fds.n_wr_fd--;
                    p_poll->u.select_fds.wr_fd[i] =
                        p_poll->u.select_fds.wr_fd[p_poll->u.select_fds.n_wr_fd];
                    p_poll->u.select_fds.wr_aux[i] =
                        p_poll->u.select_fds.wr_aux[p_poll->u.select_fds.n_wr_fd];
                    break;
                }
        break;
    case DW_POLL:
        if (p_poll->u.poll_fds.n_pollfds == MAX_POLLFD) {
            dw_log("Exhausted number of possible fds in poll()\n");
            return -1;
        }
        for (int i = 0; i < p_poll->u.poll_fds.n_pollfds; i++) {
            struct pollfd *pev = &p_poll->u.poll_fds.pollfds[i];
            if (pev->fd == fd) {
                if (rd)
                    pev->events &= ~EPOLLIN;
                if (wr)
                    pev->events &= ~EPOLLOUT;
                if (pev->events == 0) {
                    p_poll->u.poll_fds.n_pollfds--;
                    *pev = p_poll->u.poll_fds.pollfds[p_poll->u.poll_fds.n_pollfds];
                    p_poll->u.poll_fds.aux[i] = p_poll->u.poll_fds.aux[p_poll->u.poll_fds.n_pollfds];
                }
                break;
            }
        }
        break;
    case DW_EPOLL:
        struct epoll_event ev = {
            .data.u64 = aux,
            .events = (rd ? EPOLLIN : 0) | (wr ? EPOLLOUT : 0),
        };
        if (rd | wr)
            rv = epoll_ctl(p_poll->u.epoll_fds.epollfd, EPOLL_CTL_MOD, fd, &ev);
        else
            rv = epoll_ctl(p_poll->u.epoll_fds.epollfd, EPOLL_CTL_DEL, fd, NULL);
        break;
    default:
        check(0, "Wrong dw_poll_type");
    }
    return rv;
}

int dw_poll_wait(dw_poll_t *p_poll) {
    int rv;
    switch (p_poll->poll_type) {
    case DW_SELECT:
        FD_ZERO(&p_poll->u.select_fds.rd_fds);
        FD_ZERO(&p_poll->u.select_fds.wr_fds);
        FD_ZERO(&p_poll->u.select_fds.ex_fds);
        for (int i = 0; i < p_poll->u.select_fds.n_rd_fd; i++)
            FD_SET(p_poll->u.select_fds.rd_fd[i], &p_poll->u.select_fds.rd_fds);
        for (int i = 0; i < p_poll->u.select_fds.n_wr_fd; i++)
            FD_SET(p_poll->u.select_fds.wr_fd[i], &p_poll->u.select_fds.wr_fds);
        rv = select(p_poll->u.select_fds.max_fd, &p_poll->u.select_fds.rd_fds, &p_poll->u.select_fds.wr_fds, &p_poll->u.select_fds.ex_fds, NULL);
        break;
    case DW_POLL:
        rv = poll(p_poll->u.poll_fds.pollfds, p_poll->u.poll_fds.n_pollfds, -1);
        p_poll->u.poll_fds.iter = 0;
        break;
    case DW_EPOLL:
        rv = epoll_wait(p_poll->u.epoll_fds.epollfd, p_poll->u.epoll_fds.events, MAX_POLLFD, -1);
        p_poll->u.epoll_fds.iter = 0;
        if (rv >= 0) {
            p_poll->u.epoll_fds.n_events = rv;
            rv = 0;
        }
        break;
    default:
        check(0, "Wrong dw_poll_type");
    }
    return rv;
}

int dw_poll_next(dw_poll_t *p_poll, int *rd, int *wr, uint64_t *aux) {
    int rv = 0;
    switch (p_poll->poll_type) {
    case DW_SELECT:
        while (p_poll->u.select_fds.iter < p_poll->u.select_fds.n_rd_fd && !FD_ISSET(p_poll->u.select_fds.rd_fd[p_poll->u.select_fds.iter], &p_poll->u.select_fds.rd_fds))
            p_poll->u.select_fds.iter++;
        if (p_poll->u.select_fds.iter < p_poll->u.select_fds.n_rd_fd && FD_ISSET(p_poll->u.select_fds.rd_fd[p_poll->u.select_fds.iter], &p_poll->u.select_fds.rd_fds)) {
            *rd = 1;
            *wr = 0;
            *aux = p_poll->u.select_fds.rd_aux[p_poll->u.select_fds.iter];
            return p_poll->u.select_fds.rd_fd[p_poll->u.select_fds.iter++];
        }
        while (p_poll->u.select_fds.iter < p_poll->u.select_fds.n_rd_fd + p_poll->u.select_fds.n_wr_fd && !FD_ISSET(p_poll->u.select_fds.iter - p_poll->u.select_fds.rd_fd[p_poll->u.select_fds.n_rd_fd], &p_poll->u.select_fds.wr_fds))
            p_poll->u.select_fds.iter++;
        if (p_poll->u.select_fds.iter < p_poll->u.select_fds.n_rd_fd + p_poll->u.select_fds.n_wr_fd && FD_ISSET(p_poll->u.select_fds.wr_fd[p_poll->u.select_fds.iter - p_poll->u.select_fds.n_rd_fd], &p_poll->u.select_fds.wr_fds)) {
            *rd = 0;
            *wr = 1;
            *aux = p_poll->u.select_fds.wr_aux[p_poll->u.select_fds.iter];
            return p_poll->u.select_fds.wr_fd[p_poll->u.select_fds.iter++ - p_poll->u.select_fds.n_rd_fd];
        }
        break;
    case DW_POLL:
        while (p_poll->u.poll_fds.iter < p_poll->u.poll_fds.n_pollfds && p_poll->u.poll_fds.pollfds[p_poll->u.poll_fds.iter].revents == 0)
            p_poll->u.poll_fds.iter++;
        if (p_poll->u.poll_fds.iter < p_poll->u.poll_fds.n_pollfds && p_poll->u.poll_fds.pollfds[p_poll->u.poll_fds.iter].revents != 0) {
            *rd = (p_poll->u.poll_fds.pollfds[p_poll->u.poll_fds.iter].revents | POLLIN) ? 1 : 0;
            *wr = (p_poll->u.poll_fds.pollfds[p_poll->u.poll_fds.iter].revents | POLLOUT) ? 1 : 0;
            *aux = p_poll->u.poll_fds.aux[p_poll->u.poll_fds.iter];
            return p_poll->u.poll_fds.pollfds[p_poll->u.poll_fds.iter++].fd;
        }
        break;
    case DW_EPOLL:
        if (p_poll->u.epoll_fds.iter < p_poll->u.epoll_fds.n_events && p_poll->u.epoll_fds.events[p_poll->u.epoll_fds.iter].events != 0) {
            *rd = (p_poll->u.epoll_fds.events[p_poll->u.epoll_fds.iter].events | EPOLLIN) ? 1 : 0;
            *wr = (p_poll->u.epoll_fds.events[p_poll->u.epoll_fds.iter].events | EPOLLOUT) ? 1 : 0;
            *aux = p_poll->u.epoll_fds.events[p_poll->u.epoll_fds.iter].data.u64;
            return p_poll->u.epoll_fds.events[p_poll->u.epoll_fds.iter++].data.fd;
        }
        break;
    default:
        check(0, "Wrong dw_poll_type");
    }
    return rv;
}

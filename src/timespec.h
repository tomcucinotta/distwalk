#ifndef __TIMESPEC_H__
#define __TIMESPEC_H__

#include <time.h>

static inline struct timespec ts_add(struct timespec a, struct timespec b) {
    struct timespec c;
    c.tv_sec = a.tv_sec + b.tv_sec;
    c.tv_nsec = a.tv_nsec + b.tv_nsec;
    while (c.tv_nsec >= 1000000000) {
        c.tv_sec++;
        c.tv_nsec -= 1000000000;
    }
    return c;
}

static inline struct timespec ts_sub(struct timespec a, struct timespec b) {
    struct timespec c;
    c.tv_sec = a.tv_sec - b.tv_sec;
    c.tv_nsec = a.tv_nsec - b.tv_nsec;
    while (c.tv_nsec < 0) {
        c.tv_sec--;
        c.tv_nsec += 1000000000;
    }
    return c;
}

static inline long ts_sub_us(struct timespec a, struct timespec b) {
    struct timespec c = ts_sub(a, b);
    return (c.tv_sec * 1000000) + c.tv_nsec / 1000;
}

static inline int ts_leq(struct timespec a, struct timespec b) {
    struct timespec ts = ts_sub(a, b);
    return (((signed long) ts.tv_sec) < 0
            || (ts.tv_sec == 0 && ((signed long) ts.tv_nsec) < 0));
}

static inline int its_to_us(struct itimerspec t) {
    return t.it_value.tv_sec * 1000000 + t.it_value.tv_nsec / 1000;
}

static inline struct itimerspec us_to_its(int micros) {
    struct itimerspec timerspec = {0};
    timerspec.it_value.tv_sec = (micros / 1000000);
    timerspec.it_value.tv_nsec = (micros % 1000000) * 1000;
    return timerspec;
}

#endif

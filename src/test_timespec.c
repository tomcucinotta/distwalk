#include <stdio.h>
#include <stdbool.h>

#include "timespec.h"
#include "dw_debug.h"


bool test_ts_add() {
    struct timespec ts1 = (struct timespec) { 30, 20 };
    struct timespec ts2 = (struct timespec) { 20, 10 };
    
    struct timespec ts3 = ts_add(ts1, ts2);

    if (ts3.tv_sec != 50 && ts3.tv_nsec != 30) {
        return false;
    }

    struct timespec ts4 = (struct timespec) { 0, 1000000000 };

    struct timespec ts5 = ts_add(ts3, ts4);

    if (ts5.tv_sec != 51) {
        return false;
    }

    return true;
}

bool test_ts_sub() {
    struct timespec ts1 = (struct timespec) { 30, 20 };
    struct timespec ts2 = (struct timespec) { 20, 10 };

    struct timespec ts3 = ts_sub(ts1, ts2);

    
    if (ts3.tv_sec != 10 && ts3.tv_nsec != 10) {
        return false;
    }

    struct timespec ts4 = (struct timespec) { 0, 1000000000 };

    struct timespec ts5 = ts_sub(ts3, ts4);

    if (ts5.tv_sec != 9) {
        return false;
    }

    return true;
}

bool test_ts_sub_us() {
    struct timespec ts1 = (struct timespec) { 30, 20000 };
    struct timespec ts2 = (struct timespec) { 20, 10000 };

    return ts_sub_us(ts1, ts2) == 10000010;
}

bool test_ts_leq() {
    struct timespec ts1 = (struct timespec) { 30, 20 };
    struct timespec ts2 = (struct timespec) { 20, 10 };

    if (ts_leq(ts1, ts2) == 1) {
        return false;
    }

    
    ts1 = (struct timespec) { 30, 20 };
    ts2 = (struct timespec) { 30, 10 };
    
    if (ts_leq(ts1, ts2) == 1) {
        return false;
    }

    return true;
}


int main() {
    perform_test(test_ts_add());
    perform_test(test_ts_sub());
    perform_test(test_ts_sub_us());
    perform_test(test_ts_leq());

    return 0;
}

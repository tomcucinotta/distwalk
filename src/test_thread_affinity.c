#include <stdio.h>
#include <stdbool.h>

#include "thread_affinity.h"
#include "dw_debug.h"


bool test_parser() {
    
    return true;
}

bool test_ts_sub() {
    return true;
}


int main() {
    bool rv = true;
    rv |= perform_test(test_ts_add(), rv);
    rv |= perform_test(test_ts_sub(), rv);
    rv |= perform_test(test_ts_sub_us(), rv);
    rv |= perform_test(test_ts_leq(), rv);
    return rv ? EXIT_SUCCESS : EXIT_FAILURE;
}

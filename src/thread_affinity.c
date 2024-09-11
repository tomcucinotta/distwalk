#define _GNU_SOURCE
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include "thread_affinity.h"
#include "dw_debug.h"

// Based on taskset human-readable format
void aff_list_parse(char *str, cpu_set_t* mask, int ncpu) {
    char* tok;
    int min;
    int val;
    int max;

    int step = 1;
    CPU_ZERO(mask);
    while ((tok = strsep(&str, ",")) != NULL) {
        if (sscanf(tok, "%d-%d:%d", &min, &max, &step) >= 2) {
            if (min > max) {
                int tmp = max;

                max = min;
                min = tmp;
            }
            
            check(min >= 0 && min < ncpu);
            check(max >= 0 && max < ncpu);
            check(step > 0);

            for (int i=min; i<=max; i += step) {
                CPU_SET(i, mask);
            }
        } else if (sscanf(tok, "%d-", &val) == 1 || sscanf(tok, "-%d", &val) == 1 || sscanf(tok, "%d", &val) == 1) {
            val = abs(val);
            check(val < ncpu);
            CPU_SET(val, mask);
        } else {
            fprintf(stderr, "thread_affinity parsing error: '%s' not allowed\n", tok);
            exit(EXIT_FAILURE);
        }
    }
}

int aff_pin_to(int core_id) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask);
}


int aff_it_init(cpu_set_t* mask, int ncpu) {
    int it = -1;
    aff_it_next(&it, mask, ncpu);
    
    return it;
}

void aff_it_next(int* it, cpu_set_t* mask, int ncpu) {
    do {
        *it += 1;
        *it = *it % ncpu;
    } while (!CPU_ISSET(*it, mask));
}
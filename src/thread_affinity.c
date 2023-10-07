#define _GNU_SOURCE
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include "thread_affinity.h"

// Based on taskset human-readable format
void aff_list_parse(char *str, cpu_set_t* mask, int ncpu) {
    char* tok;
    int min;
    int val;
    int max;

    CPU_ZERO(mask);
    while ((tok = strsep(&str, ",")) != NULL) {
        if (sscanf(tok, "%d-%d", &min, &max) == 2) {
            if (min > max) {
                int tmp = max;

                max = min;
                min = tmp;
            }
            
            assert(min >= 0 && min < ncpu);
            assert(max >= 0 && max < ncpu);

            for (int i=min; i<=max; i++) {
                CPU_SET(i, mask);
            }
        }
        else if (sscanf(tok, "%d", &val) == 1) {
            assert(val >= 0 && val < ncpu);
            CPU_SET(val, mask);
        }
        // else: format error
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
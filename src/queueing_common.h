#ifndef __QUEUEING_COMMON_H__
#define __QUEUEING_COMMON_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef union {
    int fd;
    uint64_t value;
    void *ptr;
} data_t;

typedef struct node_t {
	uint32_t heap_id; // for pqueue
	int key;
	data_t data;
} node_t;

#endif /* __QUEUEING_COMMON_H__ */
